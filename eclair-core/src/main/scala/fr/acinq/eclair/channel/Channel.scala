/*
 * Copyright 2019 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.eclair.channel

import akka.actor.typed.scaladsl.Behaviors
import akka.actor.typed.scaladsl.adapter.{ClassicActorContextOps, TypedActorRefOps, actorRefAdapter}
import akka.actor.{Actor, ActorContext, ActorRef, FSM, OneForOneStrategy, PossiblyHarmful, Props, SupervisorStrategy, typed}
import akka.event.Logging.MDC
import com.softwaremill.quicklens.ModifyPimp
import fr.acinq.bitcoin.Crypto.{PrivateKey, PublicKey}
import fr.acinq.bitcoin.{ByteVector32, OutPoint, Satoshi, SatoshiLong, ScriptFlags, Transaction}
import fr.acinq.eclair.Logs.LogCategory
import fr.acinq.eclair.NotificationsLogger.NotifyNodeOperator
import fr.acinq.eclair._
import fr.acinq.eclair.blockchain.OnChainWallet.MakeFundingTxResponse
import fr.acinq.eclair.blockchain._
import fr.acinq.eclair.blockchain.bitcoind.ZmqWatcher
import fr.acinq.eclair.blockchain.bitcoind.ZmqWatcher._
import fr.acinq.eclair.blockchain.bitcoind.rpc.BitcoinCoreClient
import fr.acinq.eclair.channel.Commitments.PostRevocationAction
import fr.acinq.eclair.channel.Helpers.Syncing.SyncResult
import fr.acinq.eclair.channel.Helpers.{Closing, Funding, Syncing, getRelayFees}
import fr.acinq.eclair.channel.Monitoring.Metrics.ProcessMessage
import fr.acinq.eclair.channel.Monitoring.{Metrics, Tags}
import fr.acinq.eclair.channel.publish.TxPublisher
import fr.acinq.eclair.channel.publish.TxPublisher.{PublishFinalTx, PublishReplaceableTx, PublishTx, SetChannelId}
import fr.acinq.eclair.crypto.ShaChain
import fr.acinq.eclair.crypto.keymanager.ChannelKeyManager
import fr.acinq.eclair.db.DbEventHandler.ChannelEvent.EventType
import fr.acinq.eclair.db.PendingCommandsDb
import fr.acinq.eclair.io.Peer
import fr.acinq.eclair.payment.PaymentSettlingOnChain
import fr.acinq.eclair.payment.relay.Relayer
import fr.acinq.eclair.router.Announcements
import fr.acinq.eclair.transactions.Transactions.{ClosingTx, TxOwner}
import fr.acinq.eclair.transactions._
import fr.acinq.eclair.wire.protocol._
import scodec.bits.ByteVector

import scala.collection.immutable.Queue
import scala.concurrent.ExecutionContext
import scala.concurrent.duration._
import scala.util.{Failure, Random, Success, Try}

/**
 * Created by PM on 20/08/2015.
 */

object Channel {

  case class ChannelConf(channelFlags: ChannelFlags,
                         dustLimit: Satoshi,
                         maxRemoteDustLimit: Satoshi,
                         htlcMinimum: MilliSatoshi,
                         maxHtlcValueInFlightMsat: UInt64,
                         maxAcceptedHtlcs: Int,
                         reserveToFundingRatio: Double,
                         maxReserveToFundingRatio: Double,
                         minFundingSatoshis: Satoshi,
                         maxFundingSatoshis: Satoshi,
                         toRemoteDelay: CltvExpiryDelta,
                         maxToLocalDelay: CltvExpiryDelta,
                         minDepthBlocks: Int,
                         expiryDelta: CltvExpiryDelta,
                         fulfillSafetyBeforeTimeout: CltvExpiryDelta,
                         minFinalExpiryDelta: CltvExpiryDelta,
                         maxBlockProcessingDelay: FiniteDuration,
                         maxTxPublishRetryDelay: FiniteDuration,
                         unhandledExceptionStrategy: UnhandledExceptionStrategy,
                         revocationTimeout: FiniteDuration)

  trait TxPublisherFactory {
    def spawnTxPublisher(context: ActorContext, remoteNodeId: PublicKey): typed.ActorRef[TxPublisher.Command]
  }

  case class SimpleTxPublisherFactory(nodeParams: NodeParams, watcher: typed.ActorRef[ZmqWatcher.Command], bitcoinClient: BitcoinCoreClient) extends TxPublisherFactory {
    override def spawnTxPublisher(context: ActorContext, remoteNodeId: PublicKey): typed.ActorRef[TxPublisher.Command] = {
      context.spawn(Behaviors.supervise(TxPublisher(nodeParams, remoteNodeId, TxPublisher.SimpleChildFactory(nodeParams, bitcoinClient, watcher))).onFailure(typed.SupervisorStrategy.restart), "tx-publisher")
    }
  }

  def props(nodeParams: NodeParams, wallet: OnChainChannelFunder, remoteNodeId: PublicKey, blockchain: typed.ActorRef[ZmqWatcher.Command], relayer: ActorRef, txPublisherFactory: TxPublisherFactory, origin_opt: Option[ActorRef]): Props =
    Props(new Channel(nodeParams, wallet, remoteNodeId, blockchain, relayer, txPublisherFactory, origin_opt))

  // see https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#requirements
  val ANNOUNCEMENTS_MINCONF = 6

  // https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#requirements
  val MAX_FUNDING: Satoshi = 16777216 sat // = 2^24
  val MAX_ACCEPTED_HTLCS = 483

  // We may need to rely on our peer's commit tx in certain cases (backup/restore) so we must ensure their transactions
  // can propagate through the bitcoin network (assuming bitcoin core nodes with default policies).
  // The various dust limits enforced by the bitcoin network are summarized here:
  // https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#dust-limits
  // A dust limit of 354 sat ensures all segwit outputs will relay with default relay policies.
  val MIN_DUST_LIMIT: Satoshi = 354 sat

  // we won't exchange more than this many signatures when negotiating the closing fee
  val MAX_NEGOTIATION_ITERATIONS = 20

  // this is defined in BOLT 11
  val MIN_CLTV_EXPIRY_DELTA: CltvExpiryDelta = CltvExpiryDelta(18)
  val MAX_CLTV_EXPIRY_DELTA: CltvExpiryDelta = CltvExpiryDelta(7 * 144) // one week

  // since BOLT 1.1, there is a max value for the refund delay of the main commitment tx
  val MAX_TO_SELF_DELAY: CltvExpiryDelta = CltvExpiryDelta(2016)

  // as a fundee, we will wait that many blocks for the funding tx to confirm (funder will rely on the funding tx being double-spent)
  val FUNDING_TIMEOUT_FUNDEE = 2016

  // pruning occurs if no new update has been received in two weeks (BOLT 7)
  val REFRESH_CHANNEL_UPDATE_INTERVAL: FiniteDuration = 10 days

  case class BroadcastChannelUpdate(reason: BroadcastReason)

  // @formatter:off
  sealed trait BroadcastReason
  case object PeriodicRefresh extends BroadcastReason
  case object Reconnected extends BroadcastReason
  case object AboveReserve extends BroadcastReason

  private[channel] sealed trait BitcoinEvent extends PossiblyHarmful
  private[channel] case object BITCOIN_FUNDING_PUBLISH_FAILED extends BitcoinEvent
  private[channel] case object BITCOIN_FUNDING_TIMEOUT extends BitcoinEvent
  // @formatter:on

  case object TickChannelOpenTimeout

  // we will receive this message when we waited too long for a revocation for that commit number (NB: we explicitly specify the peer to allow for testing)
  case class RevocationTimeout(remoteCommitNumber: Long, peer: ActorRef)

  /** We don't immediately process [[CurrentBlockHeight]] to avoid herd effects */
  case class ProcessCurrentBlockHeight(c: CurrentBlockHeight)

  // @formatter:off
  /** What do we do if we have a local unhandled exception. */
  sealed trait UnhandledExceptionStrategy
  object UnhandledExceptionStrategy {
    /** Ask our counterparty to close the channel. This may be the best choice for smaller loosely administered nodes.*/
    case object LocalClose extends UnhandledExceptionStrategy
    /** Just log an error and stop the node. May be better for larger nodes, to prevent unwanted mass force-close.*/
    case object Stop extends UnhandledExceptionStrategy
  }
  // @formatter:on

}

class Channel(val nodeParams: NodeParams, val wallet: OnChainChannelFunder, val remoteNodeId: PublicKey, val blockchain: typed.ActorRef[ZmqWatcher.Command], relayer: ActorRef, txPublisherFactory: Channel.TxPublisherFactory, val origin_opt: Option[ActorRef] = None)(implicit val ec: ExecutionContext = ExecutionContext.Implicits.global)
  extends FSM[ChannelState, ChannelStateData] with FSMDiagnosticActorLogging[ChannelState, ChannelStateData]
  with ErrorHandlers
  with ChannelOpenSingle
  {

  import Channel._

  val keyManager: ChannelKeyManager = nodeParams.channelKeyManager

  // we pass these to helpers classes so that they have the logging context
  implicit def implicitLog: akka.event.DiagnosticLoggingAdapter = diagLog

  // we assume that the peer is the channel's parent
  val peer = context.parent
  // noinspection ActorMutableStateInspection
  // the last active connection we are aware of; note that the peer manages connections and asynchronously notifies
  // the channel, which means that if we get disconnected, the previous active connection will die and some messages will
  // be sent to dead letters, before the channel gets notified of the disconnection; knowing that this will happen, we
  // choose to not make this an Option (that would be None before the first connection), and instead embrace the fact
  // that the active connection may point to dead letters at all time
  var activeConnection = context.system.deadLetters

  val txPublisher = txPublisherFactory.spawnTxPublisher(context, remoteNodeId)

  // this will be used to detect htlc timeouts
  context.system.eventStream.subscribe(self, classOf[CurrentBlockHeight])
  // the constant delay by which we delay processing of blocks (it will be smoothened among all channels)
  private val blockProcessingDelay = Random.nextLong(nodeParams.channelConf.maxBlockProcessingDelay.toMillis + 1).millis
  // this will be used to make sure the current commitment fee is up-to-date
  context.system.eventStream.subscribe(self, classOf[CurrentFeerates])

  /*
          8888888 888b    888 8888888 88888888888
            888   8888b   888   888       888
            888   88888b  888   888       888
            888   888Y88b 888   888       888
            888   888 Y88b888   888       888
            888   888  Y88888   888       888
            888   888   Y8888   888       888
          8888888 888    Y888 8888888     888
   */

  /*
                                                NEW
                              FUNDER                            FUNDEE
                                 |                                |
                                 |          open_channel          |WAIT_FOR_OPEN_CHANNEL
                                 |------------------------------->|
          WAIT_FOR_ACCEPT_CHANNEL|                                |
                                 |         accept_channel         |
                                 |<-------------------------------|
                                 |                                |WAIT_FOR_FUNDING_CREATED
                                 |        funding_created         |
                                 |------------------------------->|
          WAIT_FOR_FUNDING_SIGNED|                                |
                                 |         funding_signed         |
                                 |<-------------------------------|
          WAIT_FOR_FUNDING_LOCKED|                                |WAIT_FOR_FUNDING_LOCKED
                                 | funding_locked  funding_locked |
                                 |---------------  ---------------|
                                 |               \/               |
                                 |               /\               |
                                 |<--------------  -------------->|
                           NORMAL|                                |NORMAL
   */

  startWith(WAIT_FOR_INIT_INTERNAL, DATA_WAIT_FOR_INIT_INTERNAL())

  when(WAIT_FOR_INIT_INTERNAL)(handleExceptions {
    case Event(initFunder@INPUT_INIT_FUNDER(temporaryChannelId, fundingSatoshis, pushMsat, initialFeeratePerKw, fundingTxFeeratePerKw, localParams, remote, remoteInit, channelFlags, channelConfig, channelType), _: DATA_WAIT_FOR_INIT_INTERNAL) =>
      context.system.eventStream.publish(ChannelCreated(self, peer, remoteNodeId, isFunder = true, temporaryChannelId, initialFeeratePerKw, Some(fundingTxFeeratePerKw)))
      activeConnection = remote
      txPublisher ! SetChannelId(remoteNodeId, temporaryChannelId)
      val fundingPubKey = keyManager.fundingPublicKey(localParams.fundingKeyPath).publicKey
      val channelKeyPath = keyManager.keyPath(localParams, channelConfig)
      // In order to allow TLV extensions and keep backwards-compatibility, we include an empty upfront_shutdown_script if this feature is not used
      // See https://github.com/lightningnetwork/lightning-rfc/pull/714.
      val localShutdownScript = if (Features.canUseFeature(localParams.initFeatures, remoteInit.features, Features.UpfrontShutdownScript)) localParams.defaultFinalScriptPubKey else ByteVector.empty
      val open = OpenChannel(nodeParams.chainHash,
        temporaryChannelId = temporaryChannelId,
        fundingSatoshis = fundingSatoshis,
        pushMsat = pushMsat,
        dustLimitSatoshis = localParams.dustLimit,
        maxHtlcValueInFlightMsat = localParams.maxHtlcValueInFlightMsat,
        channelReserveSatoshis = localParams.channelReserve,
        htlcMinimumMsat = localParams.htlcMinimum,
        feeratePerKw = initialFeeratePerKw,
        toSelfDelay = localParams.toSelfDelay,
        maxAcceptedHtlcs = localParams.maxAcceptedHtlcs,
        fundingPubkey = fundingPubKey,
        revocationBasepoint = keyManager.revocationPoint(channelKeyPath).publicKey,
        paymentBasepoint = localParams.walletStaticPaymentBasepoint.getOrElse(keyManager.paymentPoint(channelKeyPath).publicKey),
        delayedPaymentBasepoint = keyManager.delayedPaymentPoint(channelKeyPath).publicKey,
        htlcBasepoint = keyManager.htlcPoint(channelKeyPath).publicKey,
        firstPerCommitmentPoint = keyManager.commitmentPoint(channelKeyPath, 0),
        channelFlags = channelFlags,
        tlvStream = TlvStream(
          ChannelTlv.UpfrontShutdownScriptTlv(localShutdownScript),
          ChannelTlv.ChannelTypeTlv(channelType)
        ))
      goto(WAIT_FOR_ACCEPT_CHANNEL) using DATA_WAIT_FOR_ACCEPT_CHANNEL(initFunder, open) sending open

    case Event(inputFundee@INPUT_INIT_FUNDEE(_, localParams, remote, _, _, _), _: DATA_WAIT_FOR_INIT_INTERNAL) if !localParams.isFunder =>
      activeConnection = remote
      txPublisher ! SetChannelId(remoteNodeId, inputFundee.temporaryChannelId)
      goto(WAIT_FOR_OPEN_CHANNEL) using DATA_WAIT_FOR_OPEN_CHANNEL(inputFundee)

    case Event(INPUT_RESTORED(data), _) =>
      log.debug("restoring channel")
      context.system.eventStream.publish(ChannelRestored(self, data.channelId, peer, remoteNodeId, data))
      txPublisher ! SetChannelId(remoteNodeId, data.channelId)
      data match {
        // NB: order matters!
        case closing: ChannelData.Closing if Closing.nothingAtStake(closing) =>
          log.info("we have nothing at stake, going straight to CLOSED")
          goto(CLOSED) using DATA_CLOSED(Some(closing))
        case closing: ChannelData.Closing =>
          val isFunder = closing.commitments.localParams.isFunder
          // we don't put back the WatchSpent if the commitment tx has already been published and the spending tx already reached mindepth
          val closingType_opt = Closing.isClosingTypeAlreadyKnown(closing)
          log.info(s"channel is closing (closingType=${closingType_opt.map(c => EventType.Closed(c).label).getOrElse("UnknownYet")})")
          // if the closing type is known:
          // - there is no need to watch the funding tx because it has already been spent and the spending tx has already reached mindepth
          // - there is no need to attempt to publish transactions for other type of closes
          closingType_opt match {
            case Some(c: Closing.MutualClose) =>
              doPublish(c.tx, isFunder)
            case Some(c: Closing.LocalClose) =>
              doPublish(c.localCommitPublished, closing.commitments)
            case Some(c: Closing.RemoteClose) =>
              doPublish(c.remoteCommitPublished, closing.commitments)
            case Some(c: Closing.RecoveryClose) =>
              doPublish(c.remoteCommitPublished, closing.commitments)
            case Some(c: Closing.RevokedClose) =>
              doPublish(c.revokedCommitPublished)
            case None =>
              // in all other cases we need to be ready for any type of closing
              watchFundingTx(data.commitments, closing.spendingTxs.map(_.txid).toSet)
              closing.mutualClosePublished.foreach(mcp => doPublish(mcp, isFunder))
              closing.localCommitPublished.foreach(lcp => doPublish(lcp, closing.commitments))
              closing.remoteCommitPublished.foreach(rcp => doPublish(rcp, closing.commitments))
              closing.nextRemoteCommitPublished.foreach(rcp => doPublish(rcp, closing.commitments))
              closing.revokedCommitPublished.foreach(doPublish)
              closing.futureRemoteCommitPublished.foreach(rcp => doPublish(rcp, closing.commitments))

              // if commitment number is zero, we also need to make sure that the funding tx has been published
              if (closing.commitments.localCommit.index == 0 && closing.commitments.remoteCommit.index == 0) {
                blockchain ! GetTxWithMeta(self, closing.commitments.commitInput.outPoint.txid)
              }
          }
          // no need to go OFFLINE, we can directly switch to CLOSING
          if (closing.waitingSince.toLong > 1_500_000_000) {
            // we were using timestamps instead of block heights when the channel was created: we reset it *and* we use block heights
            goto(CLOSING) using DATA_CLOSING(closing.copy(waitingSince = nodeParams.currentBlockHeight)) storing()
          } else {
            goto(CLOSING) using DATA_CLOSING(closing)
          }

        case normal: ChannelData.Normal =>
          watchFundingTx(data.commitments)
          context.system.eventStream.publish(ShortChannelIdAssigned(self, normal.channelId, normal.channelUpdate.shortChannelId, None))

          // we check the configuration because the values for channel_update may have changed while eclair was down
          val fees = getRelayFees(nodeParams, remoteNodeId, data.commitments)
          if (fees.feeBase != normal.channelUpdate.feeBaseMsat ||
            fees.feeProportionalMillionths != normal.channelUpdate.feeProportionalMillionths ||
            nodeParams.channelConf.expiryDelta != normal.channelUpdate.cltvExpiryDelta) {
            log.info("refreshing channel_update due to configuration changes")
            self ! CMD_UPDATE_RELAY_FEE(ActorRef.noSender, fees.feeBase, fees.feeProportionalMillionths, Some(nodeParams.channelConf.expiryDelta))
          }
          // we need to periodically re-send channel updates, otherwise channel will be considered stale and get pruned by network
          // we take into account the date of the last update so that we don't send superfluous updates when we restart the app
          val periodicRefreshInitialDelay = Helpers.nextChannelUpdateRefresh(normal.channelUpdate.timestamp)
          context.system.scheduler.scheduleWithFixedDelay(initialDelay = periodicRefreshInitialDelay, delay = REFRESH_CHANNEL_UPDATE_INTERVAL, receiver = self, message = BroadcastChannelUpdate(PeriodicRefresh))

          goto(OFFLINE) using DATA_OFFLINE(normal)

        case funding: ChannelData.WaitingForFundingConfirmed =>
          watchFundingTx(funding.commitments)
          // we make sure that the funding tx has been published
          blockchain ! GetTxWithMeta(self, funding.commitments.commitInput.outPoint.txid)
          if (funding.waitingSince.toLong > 1_500_000_000) {
            // we were using timestamps instead of block heights when the channel was created: we reset it *and* we use block heights
            goto(OFFLINE) using DATA_OFFLINE(funding.copy(waitingSince = nodeParams.currentBlockHeight)) storing()
          } else {
            goto(OFFLINE) using DATA_OFFLINE(funding)
          }

        case _ =>
          watchFundingTx(data.commitments)
          goto(OFFLINE) using DATA_OFFLINE(data)
      }

    case Event(c: CloseCommand, d) =>
      channelOpenReplyToUser(Right(ChannelOpenResponse.ChannelClosed(d.channelId)))
      handleFastClose(c, d.channelId)

    case Event(TickChannelOpenTimeout, _) =>
      channelOpenReplyToUser(Left(LocalError(new RuntimeException("open channel cancelled, took too long"))))
      goto(CLOSED) using DATA_CLOSED(None)
  })

  when(WAIT_FOR_FUNDING_CREATED)(handleExceptions {
    case Event(FundingCreated(_, fundingTxHash, fundingTxOutputIndex, remoteSig, _), DATA_WAIT_FOR_FUNDING_CREATED(temporaryChannelId, localParams, remoteParams, fundingAmount, pushMsat, initialFeeratePerKw, remoteFirstPerCommitmentPoint, channelFlags, channelConfig, channelFeatures, _)) =>
      // they fund the channel with their funding tx, so the money is theirs (but we are paid pushMsat)
      Funding.makeFirstCommitTxs(keyManager, channelConfig, channelFeatures, temporaryChannelId, localParams, remoteParams, fundingAmount, pushMsat, initialFeeratePerKw, fundingTxHash, fundingTxOutputIndex, remoteFirstPerCommitmentPoint) match {
        case Left(ex) => handleLocalError(ex, None)
        case Right((localSpec, localCommitTx, remoteSpec, remoteCommitTx)) =>
          // check remote signature validity
          val fundingPubKey = keyManager.fundingPublicKey(localParams.fundingKeyPath)
          val localSigOfLocalTx = keyManager.sign(localCommitTx, fundingPubKey, TxOwner.Local, channelFeatures.commitmentFormat)
          val signedLocalCommitTx = Transactions.addSigs(localCommitTx, fundingPubKey.publicKey, remoteParams.fundingPubKey, localSigOfLocalTx, remoteSig)
          Transactions.checkSpendable(signedLocalCommitTx) match {
            case Failure(_) => handleLocalError(InvalidCommitmentSignature(temporaryChannelId, signedLocalCommitTx.tx), None)
            case Success(_) =>
              val localSigOfRemoteTx = keyManager.sign(remoteCommitTx, fundingPubKey, TxOwner.Remote, channelFeatures.commitmentFormat)
              val channelId = toLongId(fundingTxHash, fundingTxOutputIndex)
              // watch the funding tx transaction
              val commitInput = localCommitTx.input
              val fundingSigned = FundingSigned(
                channelId = channelId,
                signature = localSigOfRemoteTx
              )
              val commitments = Commitments(channelId, channelConfig, channelFeatures, localParams, remoteParams, channelFlags,
                LocalCommit(0, localSpec, CommitTxAndRemoteSig(localCommitTx, remoteSig), htlcTxsAndRemoteSigs = Nil), RemoteCommit(0, remoteSpec, remoteCommitTx.tx.txid, remoteFirstPerCommitmentPoint),
                LocalChanges(Nil, Nil, Nil), RemoteChanges(Nil, Nil, Nil),
                localNextHtlcId = 0L, remoteNextHtlcId = 0L,
                originChannels = Map.empty,
                remoteNextCommitInfo = Right(randomKey().publicKey), // we will receive their next per-commitment point in the next message, so we temporarily put a random byte array,
                commitInput, ShaChain.init)
              peer ! ChannelIdAssigned(self, remoteNodeId, temporaryChannelId, channelId) // we notify the peer asap so it knows how to route messages
              txPublisher ! SetChannelId(remoteNodeId, channelId)
              context.system.eventStream.publish(ChannelIdAssigned(self, remoteNodeId, temporaryChannelId, channelId))
              context.system.eventStream.publish(ChannelSignatureReceived(self, commitments))
              // NB: we don't send a ChannelSignatureSent for the first commit
              log.info(s"waiting for them to publish the funding tx for channelId=$channelId fundingTxid=${commitInput.outPoint.txid}")
              watchFundingTx(commitments)
              val fundingMinDepth = Helpers.minDepthForFunding(nodeParams.channelConf, fundingAmount)
              blockchain ! WatchFundingConfirmed(self, commitInput.outPoint.txid, fundingMinDepth)
              goto(WAIT_FOR_FUNDING_CONFIRMED) using DATA_WAIT_FOR_FUNDING_CONFIRMED(ChannelData.WaitingForFundingConfirmed(commitments, None, nodeParams.currentBlockHeight, None, Right(fundingSigned))) storing() sending fundingSigned
          }
      }

    case Event(c: CloseCommand, d: DATA_WAIT_FOR_FUNDING_CREATED) =>
      channelOpenReplyToUser(Right(ChannelOpenResponse.ChannelClosed(d.temporaryChannelId)))
      handleFastClose(c, d.temporaryChannelId)

    case Event(e: Error, _: DATA_WAIT_FOR_FUNDING_CREATED) => handleRemoteError(e)

    case Event(INPUT_DISCONNECTED, _) => goto(CLOSED) using DATA_CLOSED(None)
  })

  when(WAIT_FOR_FUNDING_SIGNED)(handleExceptions {
    case Event(msg@FundingSigned(_, remoteSig, _), d: DATA_WAIT_FOR_FUNDING_SIGNED) =>
      // we make sure that their sig checks out and that our first commit tx is spendable
      val fundingPubKey = keyManager.fundingPublicKey(d.localParams.fundingKeyPath)
      val localSigOfLocalTx = keyManager.sign(d.localCommitTx, fundingPubKey, TxOwner.Local, d.channelFeatures.commitmentFormat)
      val signedLocalCommitTx = Transactions.addSigs(d.localCommitTx, fundingPubKey.publicKey, d.remoteParams.fundingPubKey, localSigOfLocalTx, remoteSig)
      Transactions.checkSpendable(signedLocalCommitTx) match {
        case Failure(cause) =>
          // we rollback the funding tx, it will never be published
          wallet.rollback(d.fundingTx)
          channelOpenReplyToUser(Left(LocalError(cause)))
          handleLocalError(InvalidCommitmentSignature(d.channelId, signedLocalCommitTx.tx), Some(msg))
        case Success(_) =>
          val commitInput = d.localCommitTx.input
          val commitments = Commitments(d.channelId, d.channelConfig, d.channelFeatures, d.localParams, d.remoteParams, d.channelFlags,
            LocalCommit(0, d.localSpec, CommitTxAndRemoteSig(d.localCommitTx, remoteSig), htlcTxsAndRemoteSigs = Nil), d.remoteCommit,
            LocalChanges(Nil, Nil, Nil), RemoteChanges(Nil, Nil, Nil),
            localNextHtlcId = 0L, remoteNextHtlcId = 0L,
            originChannels = Map.empty,
            remoteNextCommitInfo = Right(randomKey().publicKey), // we will receive their next per-commitment point in the next message, so we temporarily put a random byte array
            commitInput, ShaChain.init)
          val blockHeight = nodeParams.currentBlockHeight
          context.system.eventStream.publish(ChannelSignatureReceived(self, commitments))
          log.info(s"publishing funding tx for channelId=${d.channelId} fundingTxid=${commitInput.outPoint.txid}")
          watchFundingTx(commitments)
          blockchain ! WatchFundingConfirmed(self, commitInput.outPoint.txid, nodeParams.channelConf.minDepthBlocks)
          log.info(s"committing txid=${d.fundingTx.txid}")

          // we will publish the funding tx only after the channel state has been written to disk because we want to
          // make sure we first persist the commitment that returns back the funds to us in case of problem
          def publishFundingTx(): Unit = {
            wallet.commit(d.fundingTx).onComplete {
              case Success(true) =>
                context.system.eventStream.publish(TransactionPublished(commitments.channelId, remoteNodeId, d.fundingTx, d.fundingTxFee, "funding"))
                channelOpenReplyToUser(Right(ChannelOpenResponse.ChannelOpened(d.channelId)))
              case Success(false) =>
                channelOpenReplyToUser(Left(LocalError(new RuntimeException("couldn't publish funding tx"))))
                self ! BITCOIN_FUNDING_PUBLISH_FAILED // fail-fast: this should be returned only when we are really sure the tx has *not* been published
              case Failure(t) =>
                channelOpenReplyToUser(Left(LocalError(t)))
                log.error(t, s"error while committing funding tx: ") // tx may still have been published, can't fail-fast
            }
          }

          goto(WAIT_FOR_FUNDING_CONFIRMED) using DATA_WAIT_FOR_FUNDING_CONFIRMED(ChannelData.WaitingForFundingConfirmed(commitments, Some(d.fundingTx), blockHeight, None, Left(d.lastSent))) storing() calling publishFundingTx()
      }

    case Event(c: CloseCommand, d: DATA_WAIT_FOR_FUNDING_SIGNED) =>
      // we rollback the funding tx, it will never be published
      wallet.rollback(d.fundingTx)
      channelOpenReplyToUser(Right(ChannelOpenResponse.ChannelClosed(d.channelId)))
      handleFastClose(c, d.channelId)

    case Event(e: Error, d: DATA_WAIT_FOR_FUNDING_SIGNED) =>
      // we rollback the funding tx, it will never be published
      wallet.rollback(d.fundingTx)
      channelOpenReplyToUser(Left(RemoteError(e)))
      handleRemoteError(e)

    case Event(INPUT_DISCONNECTED, d: DATA_WAIT_FOR_FUNDING_SIGNED) =>
      // we rollback the funding tx, it will never be published
      wallet.rollback(d.fundingTx)
      channelOpenReplyToUser(Left(LocalError(new RuntimeException("disconnected"))))
      goto(CLOSED) using DATA_CLOSED(None)

    case Event(TickChannelOpenTimeout, d: DATA_WAIT_FOR_FUNDING_SIGNED) =>
      // we rollback the funding tx, it will never be published
      wallet.rollback(d.fundingTx)
      channelOpenReplyToUser(Left(LocalError(new RuntimeException("open channel cancelled, took too long"))))
      goto(CLOSED) using DATA_CLOSED(None)
  })

  when(WAIT_FOR_FUNDING_CONFIRMED)(handleExceptions {
    case Event(msg: FundingLocked, d: DATA_WAIT_FOR_FUNDING_CONFIRMED) =>
      log.info(s"received their FundingLocked, deferring message")
      stay() using d.modify(_.data.deferred).setTo(Some(msg)) // no need to store, they will re-send if we get disconnected

    case Event(WatchFundingConfirmedTriggered(blockHeight, txIndex, fundingTx), d: DATA_WAIT_FOR_FUNDING_CONFIRMED) =>
      import d.data.commitments
      Try(Transaction.correctlySpends(commitments.fullySignedLocalCommitTx(keyManager).tx, Seq(fundingTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)) match {
        case Success(_) =>
          log.info(s"channelId=${d.channelId} was confirmed at blockHeight=$blockHeight txIndex=$txIndex")
          blockchain ! WatchFundingLost(self, commitments.commitInput.outPoint.txid, nodeParams.channelConf.minDepthBlocks)
          if (!commitments.localParams.isFunder) context.system.eventStream.publish(TransactionPublished(d.channelId, remoteNodeId, fundingTx, 0 sat, "funding"))
          context.system.eventStream.publish(TransactionConfirmed(d.channelId, remoteNodeId, fundingTx))
          val channelKeyPath = keyManager.keyPath(commitments.localParams, commitments.channelConfig)
          val nextPerCommitmentPoint = keyManager.commitmentPoint(channelKeyPath, 1)
          val fundingLocked = FundingLocked(d.channelId, nextPerCommitmentPoint)
          d.data.deferred.foreach(self ! _)
          // this is the temporary channel id that we will use in our channel_update message, the goal is to be able to use our channel
          // as soon as it reaches NORMAL state, and before it is announced on the network
          // (this id might be updated when the funding tx gets deeply buried, if there was a reorg in the meantime)
          val shortChannelId = ShortChannelId(blockHeight, txIndex, commitments.commitInput.outPoint.index.toInt)
          goto(WAIT_FOR_FUNDING_LOCKED) using DATA_WAIT_FOR_FUNDING_LOCKED(ChannelData.WaitingForFundingLocked(commitments, shortChannelId, fundingLocked)) storing() sending fundingLocked
        case Failure(t) =>
          log.error(t, s"rejecting channel with invalid funding tx: ${fundingTx.bin}")
          goto(CLOSED) using DATA_CLOSED(Some(d.data))
      }

    case Event(remoteAnnSigs: AnnouncementSignatures, d: DATA_WAIT_FOR_FUNDING_CONFIRMED) if d.data.commitments.announceChannel =>
      log.debug("received remote announcement signatures, delaying")
      // we may receive their announcement sigs before our watcher notifies us that the channel has reached min_conf (especially during testing when blocks are generated in bulk)
      // note: no need to persist their message, in case of disconnection they will resend it
      context.system.scheduler.scheduleOnce(2 seconds, self, remoteAnnSigs)
      stay()

    case Event(getTxResponse: GetTxWithMetaResponse, d: DATA_WAIT_FOR_FUNDING_CONFIRMED) if getTxResponse.txid == d.data.commitments.commitInput.outPoint.txid => handleGetFundingTx(getTxResponse, d.data.waitingSince, d.data.fundingTx)

    case Event(BITCOIN_FUNDING_PUBLISH_FAILED, d: DATA_WAIT_FOR_FUNDING_CONFIRMED) => handleFundingPublishFailed(d.data)

    case Event(ProcessCurrentBlockHeight(c), d: DATA_WAIT_FOR_FUNDING_CONFIRMED) => d.data.fundingTx match {
      case Some(_) => stay() // we are funder, we're still waiting for the funding tx to be confirmed
      case None if c.blockHeight - d.data.waitingSince > FUNDING_TIMEOUT_FUNDEE =>
        log.warning(s"funding tx hasn't been published in ${c.blockHeight - d.data.waitingSince} blocks")
        self ! BITCOIN_FUNDING_TIMEOUT
        stay()
      case None => stay() // let's wait longer
    }

    case Event(BITCOIN_FUNDING_TIMEOUT, d: DATA_WAIT_FOR_FUNDING_CONFIRMED) => handleFundingTimeout(d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_WAIT_FOR_FUNDING_CONFIRMED) if tx.txid == d.data.commitments.remoteCommit.txid => handleRemoteSpentCurrent(tx, d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_WAIT_FOR_FUNDING_CONFIRMED) => handleInformationLeak(tx, d.data)

    case Event(e: Error, _: DATA_WAIT_FOR_FUNDING_CONFIRMED) => handleRemoteError(e)
  })

  when(WAIT_FOR_FUNDING_LOCKED)(handleExceptions {
    case Event(FundingLocked(_, nextPerCommitmentPoint, _), d: DATA_WAIT_FOR_FUNDING_LOCKED) =>
      import d.data.{commitments, shortChannelId}
      // used to get the final shortChannelId, used in announcements (if minDepth >= ANNOUNCEMENTS_MINCONF this event will fire instantly)
      blockchain ! WatchFundingDeeplyBuried(self, commitments.commitInput.outPoint.txid, ANNOUNCEMENTS_MINCONF)
      context.system.eventStream.publish(ShortChannelIdAssigned(self, commitments.channelId, d.data.shortChannelId, None))
      // we create a channel_update early so that we can use it to send payments through this channel, but it won't be propagated to other nodes since the channel is not yet announced
      val fees = getRelayFees(nodeParams, remoteNodeId, commitments)
      val initialChannelUpdate = Announcements.makeChannelUpdate(nodeParams.chainHash, nodeParams.privateKey, remoteNodeId, shortChannelId, nodeParams.channelConf.expiryDelta, commitments.remoteParams.htlcMinimum, fees.feeBase, fees.feeProportionalMillionths, commitments.capacity.toMilliSatoshi, enable = Helpers.aboveReserve(commitments))
      // we need to periodically re-send channel updates, otherwise channel will be considered stale and get pruned by network
      context.system.scheduler.scheduleWithFixedDelay(initialDelay = REFRESH_CHANNEL_UPDATE_INTERVAL, delay = REFRESH_CHANNEL_UPDATE_INTERVAL, receiver = self, message = BroadcastChannelUpdate(PeriodicRefresh))
      goto(NORMAL) using DATA_NORMAL(ChannelData.Normal(commitments.copy(remoteNextCommitInfo = Right(nextPerCommitmentPoint)), shortChannelId, buried = false, None, initialChannelUpdate, None, None, None)) storing()

    case Event(remoteAnnSigs: AnnouncementSignatures, d: DATA_WAIT_FOR_FUNDING_LOCKED) if d.data.commitments.announceChannel =>
      log.debug("received remote announcement signatures, delaying")
      // we may receive their announcement sigs before our watcher notifies us that the channel has reached min_conf (especially during testing when blocks are generated in bulk)
      // note: no need to persist their message, in case of disconnection they will resend it
      context.system.scheduler.scheduleOnce(2 seconds, self, remoteAnnSigs)
      stay()

    case Event(WatchFundingSpentTriggered(tx), d: DATA_WAIT_FOR_FUNDING_LOCKED) if tx.txid == d.data.commitments.remoteCommit.txid => handleRemoteSpentCurrent(tx, d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_WAIT_FOR_FUNDING_LOCKED) => handleInformationLeak(tx, d.data)

    case Event(e: Error, _: DATA_WAIT_FOR_FUNDING_LOCKED) => handleRemoteError(e)
  })

  /*
          888b     d888        d8888 8888888 888b    888      888      .d88888b.   .d88888b.  8888888b.
          8888b   d8888       d88888   888   8888b   888      888     d88P" "Y88b d88P" "Y88b 888   Y88b
          88888b.d88888      d88P888   888   88888b  888      888     888     888 888     888 888    888
          888Y88888P888     d88P 888   888   888Y88b 888      888     888     888 888     888 888   d88P
          888 Y888P 888    d88P  888   888   888 Y88b888      888     888     888 888     888 8888888P"
          888  Y8P  888   d88P   888   888   888  Y88888      888     888     888 888     888 888
          888   "   888  d8888888888   888   888   Y8888      888     Y88b. .d88P Y88b. .d88P 888
          888       888 d88P     888 8888888 888    Y888      88888888 "Y88888P"   "Y88888P"  888
   */

  when(NORMAL)(handleExceptions {
    case Event(c: CMD_ADD_HTLC, d: DATA_NORMAL) if d.data.localShutdown.isDefined || d.data.remoteShutdown.isDefined =>
      // note: spec would allow us to keep sending new htlcs after having received their shutdown (and not sent ours)
      // but we want to converge as fast as possible and they would probably not route them anyway
      val error = NoMoreHtlcsClosingInProgress(d.channelId)
      handleAddHtlcCommandError(c, error, Some(d.data.channelUpdate))

    case Event(c: CMD_ADD_HTLC, d: DATA_NORMAL) =>
      Commitments.sendAdd(d.data.commitments, c, nodeParams.currentBlockHeight, nodeParams.onChainFeeConf) match {
        case Right((commitments1, add)) =>
          if (c.commit) self ! CMD_SIGN()
          context.system.eventStream.publish(AvailableBalanceChanged(self, d.channelId, d.data.shortChannelId, commitments1))
          handleCommandSuccess(c, d.modify(_.data.commitments).setTo(commitments1)) sending add
        case Left(cause) => handleAddHtlcCommandError(c, cause, Some(d.data.channelUpdate))
      }

    case Event(add: UpdateAddHtlc, d: DATA_NORMAL) =>
      Commitments.receiveAdd(d.data.commitments, add, nodeParams.onChainFeeConf) match {
        case Right(commitments1) => stay() using d.modify(_.data.commitments).setTo(commitments1)
        case Left(cause) => handleLocalError(cause, Some(add))
      }

    case Event(c: CMD_FULFILL_HTLC, d: DATA_NORMAL) =>
      Commitments.sendFulfill(d.data.commitments, c) match {
        case Right((commitments1, fulfill)) =>
          if (c.commit) self ! CMD_SIGN()
          context.system.eventStream.publish(AvailableBalanceChanged(self, d.channelId, d.data.shortChannelId, commitments1))
          handleCommandSuccess(c, d.modify(_.data.commitments).setTo(commitments1)) sending fulfill
        case Left(cause) =>
          // we acknowledge the command right away in case of failure
          handleCommandError(cause, c).acking(d.channelId, c)
      }

    case Event(fulfill: UpdateFulfillHtlc, d: DATA_NORMAL) =>
      Commitments.receiveFulfill(d.data.commitments, fulfill) match {
        case Right((commitments1, origin, htlc)) =>
          // we forward preimages as soon as possible to the upstream channel because it allows us to pull funds
          relayer ! RES_ADD_SETTLED(origin, htlc, HtlcResult.RemoteFulfill(fulfill))
          stay() using d.modify(_.data.commitments).setTo(commitments1)
        case Left(cause) => handleLocalError(cause, Some(fulfill))
      }

    case Event(c: CMD_FAIL_HTLC, d: DATA_NORMAL) =>
      Commitments.sendFail(d.data.commitments, c, nodeParams.privateKey) match {
        case Right((commitments1, fail)) =>
          if (c.commit) self ! CMD_SIGN()
          context.system.eventStream.publish(AvailableBalanceChanged(self, d.channelId, d.data.shortChannelId, commitments1))
          handleCommandSuccess(c, d.modify(_.data.commitments).setTo(commitments1)) sending fail
        case Left(cause) =>
          // we acknowledge the command right away in case of failure
          handleCommandError(cause, c).acking(d.channelId, c)
      }

    case Event(c: CMD_FAIL_MALFORMED_HTLC, d: DATA_NORMAL) =>
      Commitments.sendFailMalformed(d.data.commitments, c) match {
        case Right((commitments1, fail)) =>
          if (c.commit) self ! CMD_SIGN()
          context.system.eventStream.publish(AvailableBalanceChanged(self, d.channelId, d.data.shortChannelId, commitments1))
          handleCommandSuccess(c, d.modify(_.data.commitments).setTo(commitments1)) sending fail
        case Left(cause) =>
          // we acknowledge the command right away in case of failure
          handleCommandError(cause, c).acking(d.channelId, c)
      }

    case Event(fail: UpdateFailHtlc, d: DATA_NORMAL) =>
      Commitments.receiveFail(d.data.commitments, fail) match {
        case Right((commitments1, _, _)) => stay() using d.modify(_.data.commitments).setTo(commitments1)
        case Left(cause) => handleLocalError(cause, Some(fail))
      }

    case Event(fail: UpdateFailMalformedHtlc, d: DATA_NORMAL) =>
      Commitments.receiveFailMalformed(d.data.commitments, fail) match {
        case Right((commitments1, _, _)) => stay() using d.modify(_.data.commitments).setTo(commitments1)
        case Left(cause) => handleLocalError(cause, Some(fail))
      }

    case Event(c: CMD_UPDATE_FEE, d: DATA_NORMAL) =>
      Commitments.sendFee(d.data.commitments, c, nodeParams.onChainFeeConf) match {
        case Right((commitments1, fee)) =>
          if (c.commit) self ! CMD_SIGN()
          context.system.eventStream.publish(AvailableBalanceChanged(self, d.channelId, d.data.shortChannelId, commitments1))
          handleCommandSuccess(c, d.modify(_.data.commitments).setTo(commitments1)) sending fee
        case Left(cause) => handleCommandError(cause, c)
      }

    case Event(fee: UpdateFee, d: DATA_NORMAL) =>
      Commitments.receiveFee(d.data.commitments, fee, nodeParams.onChainFeeConf) match {
        case Right(commitments1) => stay() using d.modify(_.data.commitments).setTo(commitments1)
        case Left(cause) => handleLocalError(cause, Some(fee))
      }

    case Event(c: CMD_SIGN, d: DATA_NORMAL) =>
      import d.data.commitments
      commitments.remoteNextCommitInfo match {
        case _ if !Commitments.localHasChanges(commitments) =>
          log.debug("ignoring CMD_SIGN (nothing to sign)")
          stay()
        case Right(_) =>
          Commitments.sendCommit(commitments, keyManager) match {
            case Right((commitments1, commit)) =>
              log.debug("sending a new sig, spec:\n{}", Commitments.specs2String(commitments1))
              val nextRemoteCommit = commitments1.remoteNextCommitInfo.swap.toOption.get.nextRemoteCommit
              val nextCommitNumber = nextRemoteCommit.index
              // we persist htlc data in order to be able to claim htlc outputs in case a revoked tx is published by our
              // counterparty, so only htlcs above remote's dust_limit matter
              val trimmedHtlcs = Transactions.trimOfferedHtlcs(commitments.remoteParams.dustLimit, nextRemoteCommit.spec, commitments.commitmentFormat) ++
                Transactions.trimReceivedHtlcs(commitments.remoteParams.dustLimit, nextRemoteCommit.spec, commitments.commitmentFormat)
              trimmedHtlcs.map(_.add).foreach { htlc =>
                log.debug(s"adding paymentHash=${htlc.paymentHash} cltvExpiry=${htlc.cltvExpiry} to htlcs db for commitNumber=$nextCommitNumber")
                nodeParams.db.channels.addHtlcInfo(d.channelId, nextCommitNumber, htlc.paymentHash, htlc.cltvExpiry)
              }
              if (!Helpers.aboveReserve(commitments) && Helpers.aboveReserve(commitments1)) {
                // we just went above reserve (can't go below), let's refresh our channel_update to enable/disable it accordingly
                log.info("updating channel_update aboveReserve={}", Helpers.aboveReserve(commitments1))
                self ! BroadcastChannelUpdate(AboveReserve)
              }
              context.system.eventStream.publish(ChannelSignatureSent(self, commitments1))
              // we expect a quick response from our peer
              startSingleTimer(RevocationTimeout.toString, RevocationTimeout(commitments1.remoteCommit.index, peer), nodeParams.channelConf.revocationTimeout)
              handleCommandSuccess(c, d.modify(_.data.commitments).setTo(commitments1)).storing().sending(commit).acking(commitments1.localChanges.signed)
            case Left(cause) => handleCommandError(cause, c)
          }
        case Left(waitForRevocation) =>
          log.debug("already in the process of signing, will sign again as soon as possible")
          val commitments1 = commitments.copy(remoteNextCommitInfo = Left(waitForRevocation.copy(reSignAsap = true)))
          stay() using d.modify(_.data.commitments).setTo(commitments1)
      }

    case Event(commit: CommitSig, d: DATA_NORMAL) =>
      import d.data.commitments
      Commitments.receiveCommit(commitments, commit, keyManager) match {
        case Right((commitments1, revocation)) =>
          log.debug("received a new sig, spec:\n{}", Commitments.specs2String(commitments1))
          if (Commitments.localHasChanges(commitments1)) {
            // if we have newly acknowledged changes let's sign them
            self ! CMD_SIGN()
          }
          if (commitments.availableBalanceForSend != commitments1.availableBalanceForSend) {
            // we send this event only when our balance changes
            context.system.eventStream.publish(AvailableBalanceChanged(self, d.channelId, d.data.shortChannelId, commitments1))
          }
          context.system.eventStream.publish(ChannelSignatureReceived(self, commitments1))
          stay() using d.modify(_.data.commitments).setTo(commitments1) storing() sending revocation
        case Left(cause) => handleLocalError(cause, Some(commit))
      }

    case Event(revocation: RevokeAndAck, d: DATA_NORMAL) =>
      import d.data.commitments
      // we received a revocation because we sent a signature
      // => all our changes have been acked
      Commitments.receiveRevocation(commitments, revocation, nodeParams.onChainFeeConf.feerateToleranceFor(remoteNodeId).dustTolerance.maxExposure) match {
        case Right((commitments1, actions)) =>
          cancelTimer(RevocationTimeout.toString)
          log.debug("received a new rev, spec:\n{}", Commitments.specs2String(commitments1))
          actions.foreach {
            case PostRevocationAction.RelayHtlc(add) =>
              log.debug("forwarding incoming htlc {} to relayer", add)
              relayer ! Relayer.RelayForward(add)
            case PostRevocationAction.RejectHtlc(add) =>
              log.debug("rejecting incoming htlc {}", add)
              // NB: we don't set commit = true, we will sign all updates at once afterwards.
              self ! CMD_FAIL_HTLC(add.id, Right(TemporaryChannelFailure(d.data.channelUpdate)), commit = true)
            case PostRevocationAction.RelayFailure(result) =>
              log.debug("forwarding {} to relayer", result)
              relayer ! result
          }
          if (Commitments.localHasChanges(commitments1) && commitments.remoteNextCommitInfo.left.map(_.reSignAsap) == Left(true)) {
            self ! CMD_SIGN()
          }
          if (d.data.remoteShutdown.isDefined && !Commitments.localHasUnsignedOutgoingHtlcs(commitments1)) {
            // we were waiting for our pending htlcs to be signed before replying with our local shutdown
            val localShutdown = Shutdown(d.channelId, commitments1.localParams.defaultFinalScriptPubKey)
            // note: it means that we had pending htlcs to sign, therefore we go to SHUTDOWN, not to NEGOTIATING
            require(commitments1.remoteCommit.spec.htlcs.nonEmpty, "we must have just signed new htlcs, otherwise we would have sent our Shutdown earlier")
            goto(SHUTDOWN) using DATA_SHUTDOWN(ChannelData.ShuttingDown(commitments1, localShutdown, d.data.remoteShutdown.get, d.data.closingFeerates)) storing() sending localShutdown
          } else {
            stay() using d.modify(_.data.commitments).setTo(commitments1) storing()
          }
        case Left(cause) => handleLocalError(cause, Some(revocation))
      }

    case Event(r: RevocationTimeout, d: DATA_NORMAL) => handleRevocationTimeout(r, d.data)

    case Event(c: CMD_CLOSE, d: DATA_NORMAL) =>
      import d.data.commitments
      commitments.getLocalShutdownScript(c.scriptPubKey) match {
        case Left(e) => handleCommandError(e, c)
        case Right(localShutdownScript) =>
          if (d.data.localShutdown.isDefined) {
            handleCommandError(ClosingAlreadyInProgress(d.channelId), c)
          } else if (Commitments.localHasUnsignedOutgoingHtlcs(commitments)) {
            // NB: simplistic behavior, we could also sign-then-close
            handleCommandError(CannotCloseWithUnsignedOutgoingHtlcs(d.channelId), c)
          } else if (Commitments.localHasUnsignedOutgoingUpdateFee(commitments)) {
            handleCommandError(CannotCloseWithUnsignedOutgoingUpdateFee(d.channelId), c)
          } else {
            val shutdown = Shutdown(d.channelId, localShutdownScript)
            val d1 = d.modify(_.data.localShutdown).setTo(Some(shutdown))
              .modify(_.data.closingFeerates).setTo(c.feerates)
            handleCommandSuccess(c, d1) storing() sending shutdown
          }
      }

    case Event(remoteShutdown@Shutdown(_, remoteScriptPubKey, _), d: DATA_NORMAL) =>
      import d.data.commitments
      commitments.getRemoteShutdownScript(remoteScriptPubKey) match {
        case Left(e) =>
          log.warning(s"they sent an invalid closing script: ${e.getMessage}")
          context.system.scheduler.scheduleOnce(2 second, peer, Peer.Disconnect(remoteNodeId))
          stay() sending Warning(d.channelId, "invalid closing script")
        case Right(remoteShutdownScript) =>
          // they have pending unsigned htlcs         => they violated the spec, close the channel
          // they don't have pending unsigned htlcs
          //    we have pending unsigned htlcs
          //      we already sent a shutdown message  => spec violation (we can't send htlcs after having sent shutdown)
          //      we did not send a shutdown message
          //        we are ready to sign              => we stop sending further htlcs, we initiate a signature
          //        we are waiting for a rev          => we stop sending further htlcs, we wait for their revocation, will resign immediately after, and then we will send our shutdown message
          //    we have no pending unsigned htlcs
          //      we already sent a shutdown message
          //        there are pending signed changes  => send our shutdown message, go to SHUTDOWN
          //        there are no htlcs                => send our shutdown message, go to NEGOTIATING
          //      we did not send a shutdown message
          //        there are pending signed changes  => go to SHUTDOWN
          //        there are no htlcs                => go to NEGOTIATING
          if (Commitments.remoteHasUnsignedOutgoingHtlcs(commitments)) {
            handleLocalError(CannotCloseWithUnsignedOutgoingHtlcs(d.channelId), Some(remoteShutdown))
          } else if (Commitments.remoteHasUnsignedOutgoingUpdateFee(commitments)) {
            handleLocalError(CannotCloseWithUnsignedOutgoingUpdateFee(d.channelId), Some(remoteShutdown))
          } else if (Commitments.localHasUnsignedOutgoingHtlcs(commitments)) { // do we have unsigned outgoing htlcs?
            require(d.data.localShutdown.isEmpty, "can't have pending unsigned outgoing htlcs after having sent Shutdown")
            // are we in the middle of a signature?
            commitments.remoteNextCommitInfo match {
              case Left(waitForRevocation) =>
                // yes, let's just schedule a new signature ASAP, which will include all pending unsigned changes
                val commitments1 = commitments.copy(remoteNextCommitInfo = Left(waitForRevocation.copy(reSignAsap = true)))
                // in the meantime we won't send new changes
                val d1 = d.modify(_.data.commitments).setTo(commitments1)
                  .modify(_.data.remoteShutdown).setTo(Some(remoteShutdown))
                stay() using d1
              case Right(_) =>
                // no, let's sign right away
                self ! CMD_SIGN()
                // in the meantime we won't send new changes
                stay() using d.modify(_.data.remoteShutdown).setTo(Some(remoteShutdown))
            }
          } else {
            // so we don't have any unsigned outgoing changes
            val (localShutdown, sendList) = d.data.localShutdown match {
              case Some(localShutdown) =>
                (localShutdown, Nil)
              case None =>
                val localShutdown = Shutdown(d.channelId, commitments.localParams.defaultFinalScriptPubKey)
                // we need to send our shutdown if we didn't previously
                (localShutdown, localShutdown :: Nil)
            }
            // are there pending signed changes on either side? we need to have received their last revocation!
            if (commitments.hasNoPendingHtlcsOrFeeUpdate) {
              // there are no pending signed changes, let's go directly to NEGOTIATING
              if (commitments.localParams.isFunder) {
                // we are funder, need to initiate the negotiation by sending the first closing_signed
                val (closingTx, closingSigned) = Closing.makeFirstClosingTx(keyManager, commitments, localShutdown.scriptPubKey, remoteShutdownScript, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets, d.data.closingFeerates)
                goto(NEGOTIATING) using DATA_NEGOTIATING(ChannelData.Negotiating(commitments, localShutdown, remoteShutdown, List(List(ClosingTxProposed(closingTx, closingSigned))), bestUnpublishedClosingTx_opt = None)) storing() sending sendList :+ closingSigned
              } else {
                // we are fundee, will wait for their closing_signed
                goto(NEGOTIATING) using DATA_NEGOTIATING(ChannelData.Negotiating(commitments, localShutdown, remoteShutdown, closingTxProposed = List(List()), bestUnpublishedClosingTx_opt = None)) storing() sending sendList
              }
            } else {
              // there are some pending signed changes, we need to wait for them to be settled (fail/fulfill htlcs and sign fee updates)
              goto(SHUTDOWN) using DATA_SHUTDOWN(ChannelData.ShuttingDown(commitments, localShutdown, remoteShutdown, d.data.closingFeerates)) storing() sending sendList
            }
          }
      }

    case Event(ProcessCurrentBlockHeight(c), d: DATA_NORMAL) => handleNewBlock(c, d.data)

    case Event(c: CurrentFeerates, d: DATA_NORMAL) => handleCurrentFeerate(c, d.data)

    case Event(WatchFundingDeeplyBuriedTriggered(blockHeight, txIndex, _), d: DATA_NORMAL) if d.data.channelAnnouncement.isEmpty =>
      import d.data.{channelUpdate, commitments, shortChannelId}
      val shortChannelId1 = ShortChannelId(blockHeight, txIndex, commitments.commitInput.outPoint.index.toInt)
      log.info(s"funding tx is deeply buried at blockHeight=$blockHeight txIndex=$txIndex shortChannelId=$shortChannelId1")
      // if final shortChannelId is different from the one we had before, we need to re-announce it
      val channelUpdate1 = if (shortChannelId != shortChannelId1) {
        log.info(s"short channel id changed, probably due to a chain reorg: old=$shortChannelId new=$shortChannelId1")
        // we need to re-announce this shortChannelId
        context.system.eventStream.publish(ShortChannelIdAssigned(self, d.channelId, shortChannelId1, Some(shortChannelId)))
        // we re-announce the channelUpdate for the same reason
        Announcements.makeChannelUpdate(nodeParams.chainHash, nodeParams.privateKey, remoteNodeId, shortChannelId1, channelUpdate.cltvExpiryDelta, channelUpdate.htlcMinimumMsat, channelUpdate.feeBaseMsat, channelUpdate.feeProportionalMillionths, commitments.capacity.toMilliSatoshi, enable = Helpers.aboveReserve(commitments))
      } else {
        channelUpdate
      }
      val localAnnSigs_opt = if (commitments.announceChannel) {
        // if channel is public we need to send our announcement_signatures in order to generate the channel_announcement
        Some(Helpers.makeAnnouncementSignatures(nodeParams, commitments, shortChannelId1))
      } else {
        None
      }
      // we use goto() instead of stay() because we want to fire transitions
      val d1 = d.modify(_.data.shortChannelId).setTo(shortChannelId1)
        .modify(_.data.channelUpdate).setTo(channelUpdate1)
        .modify(_.data.buried).setTo(true)
      goto(NORMAL) using d1 storing() sending localAnnSigs_opt.toSeq

    case Event(remoteAnnSigs: AnnouncementSignatures, d: DATA_NORMAL) if d.data.commitments.announceChannel =>
      import d.data.{commitments, shortChannelId}
      // channels are publicly announced if both parties want it (defined as feature bit)
      if (d.data.buried) {
        // we are aware that the channel has reached enough confirmations
        // we already had sent our announcement_signatures but we don't store them so we need to recompute it
        val localAnnSigs = Helpers.makeAnnouncementSignatures(nodeParams, commitments, shortChannelId)
        d.data.channelAnnouncement match {
          case None =>
            require(shortChannelId == remoteAnnSigs.shortChannelId, s"shortChannelId mismatch: local=$shortChannelId remote=${remoteAnnSigs.shortChannelId}")
            log.info(s"announcing channelId=${d.channelId} on the network with shortId=$shortChannelId")
            import commitments.{localParams, remoteParams}
            val fundingPubKey = keyManager.fundingPublicKey(localParams.fundingKeyPath)
            val channelAnn = Announcements.makeChannelAnnouncement(nodeParams.chainHash, localAnnSigs.shortChannelId, nodeParams.nodeId, remoteParams.nodeId, fundingPubKey.publicKey, remoteParams.fundingPubKey, localAnnSigs.nodeSignature, remoteAnnSigs.nodeSignature, localAnnSigs.bitcoinSignature, remoteAnnSigs.bitcoinSignature)
            if (!Announcements.checkSigs(channelAnn)) {
              handleLocalError(InvalidAnnouncementSignatures(d.channelId, remoteAnnSigs), Some(remoteAnnSigs))
            } else {
              // we use goto() instead of stay() because we want to fire transitions
              goto(NORMAL) using d.modify(_.data.channelAnnouncement).setTo(Some(channelAnn)) storing()
            }
          case Some(_) =>
            // they have sent their announcement sigs, but we already have a valid channel announcement
            // this can happen if our announcement_signatures was lost during a disconnection
            // specs says that we "MUST respond to the first announcement_signatures message after reconnection with its own announcement_signatures message"
            // current implementation always replies to announcement_signatures, not only the first time
            // TODO: we should only be nice once, current behaviour opens way to DOS, but this should be handled higher in the stack anyway
            log.info("re-sending our announcement sigs")
            stay() sending localAnnSigs
        }
      } else {
        // our watcher didn't notify yet that the tx has reached ANNOUNCEMENTS_MINCONF confirmations, let's delay remote's message
        // note: no need to persist their message, in case of disconnection they will resend it
        log.debug("received remote announcement signatures, delaying")
        context.system.scheduler.scheduleOnce(5 seconds, self, remoteAnnSigs)
        stay()
      }

    case Event(c: CMD_UPDATE_RELAY_FEE, d: DATA_NORMAL) =>
      import d.data.{channelUpdate, commitments, shortChannelId}
      val channelUpdate1 = Announcements.makeChannelUpdate(nodeParams.chainHash, nodeParams.privateKey, remoteNodeId, shortChannelId, c.cltvExpiryDelta_opt.getOrElse(channelUpdate.cltvExpiryDelta), channelUpdate.htlcMinimumMsat, c.feeBase, c.feeProportionalMillionths, commitments.capacity.toMilliSatoshi, enable = Helpers.aboveReserve(commitments))
      log.info(s"updating relay fees: prev={} next={}", channelUpdate.toStringShort, channelUpdate1.toStringShort)
      val replyTo = if (c.replyTo == ActorRef.noSender) sender() else c.replyTo
      replyTo ! RES_SUCCESS(c, d.channelId)
      // we use goto() instead of stay() because we want to fire transitions
      goto(NORMAL) using d.modify(_.data.channelUpdate).setTo(channelUpdate1) storing()

    case Event(BroadcastChannelUpdate(reason), d: DATA_NORMAL) =>
      import d.data.{channelUpdate, commitments, shortChannelId}
      val age = TimestampSecond.now() - channelUpdate.timestamp
      val channelUpdate1 = Announcements.makeChannelUpdate(nodeParams.chainHash, nodeParams.privateKey, remoteNodeId, shortChannelId, channelUpdate.cltvExpiryDelta, channelUpdate.htlcMinimumMsat, channelUpdate.feeBaseMsat, channelUpdate.feeProportionalMillionths, commitments.capacity.toMilliSatoshi, enable = Helpers.aboveReserve(commitments))
      reason match {
        case Reconnected if commitments.announceChannel && Announcements.areSame(channelUpdate1, channelUpdate) && age < REFRESH_CHANNEL_UPDATE_INTERVAL =>
          // we already sent an identical channel_update not long ago (flapping protection in case we keep being disconnected/reconnected)
          log.debug("not sending a new identical channel_update, current one was created {} days ago", age.toDays)
          stay()
        case _ =>
          log.debug("refreshing channel_update announcement (reason={})", reason)
          // we use goto() instead of stay() because we want to fire transitions
          goto(NORMAL) using d.modify(_.data.channelUpdate).setTo(channelUpdate1) storing()
      }

    case Event(WatchFundingSpentTriggered(tx), d: DATA_NORMAL) if tx.txid == d.data.commitments.remoteCommit.txid => handleRemoteSpentCurrent(tx, d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_NORMAL) if d.data.commitments.remoteNextCommitInfo.left.toOption.exists(_.nextRemoteCommit.txid == tx.txid) => handleRemoteSpentNext(tx, d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_NORMAL) => handleRemoteSpentOther(tx, d.data)

    case Event(INPUT_DISCONNECTED, d: DATA_NORMAL) =>
      import d.data.{channelUpdate, commitments, shortChannelId}
      // we cancel the timer that would have made us send the enabled update after reconnection (flappy channel protection)
      cancelTimer(Reconnected.toString)
      // if we have pending unsigned htlcs, then we cancel them and generate an update with the disabled flag set, that will be returned to the sender in a temporary channel failure
      val d1 = if (commitments.localChanges.proposed.collectFirst { case add: UpdateAddHtlc => add }.isDefined) {
        log.debug("updating channel_update announcement (reason=disabled)")
        val channelUpdate1 = Announcements.makeChannelUpdate(nodeParams.chainHash, nodeParams.privateKey, remoteNodeId, shortChannelId, channelUpdate.cltvExpiryDelta, channelUpdate.htlcMinimumMsat, channelUpdate.feeBaseMsat, channelUpdate.feeProportionalMillionths, commitments.capacity.toMilliSatoshi, enable = false)
        // NB: the htlcs stay() in the commitments.localChange, they will be cleaned up after reconnection
        commitments.localChanges.proposed.collect {
          case add: UpdateAddHtlc => relayer ! RES_ADD_SETTLED(commitments.originChannels(add.id), add, HtlcResult.DisconnectedBeforeSigned(channelUpdate1))
        }
        d.data.copy(channelUpdate = channelUpdate1)
      } else {
        d.data
      }
      goto(OFFLINE) using DATA_OFFLINE(d1)

    case Event(e: Error, _: DATA_NORMAL) => handleRemoteError(e)

    case Event(_: FundingLocked, _: DATA_NORMAL) => stay() // will happen after a reconnection if no updates were ever committed to the channel

  })

  /*
           .d8888b.  888      .d88888b.   .d8888b. 8888888 888b    888  .d8888b.
          d88P  Y88b 888     d88P" "Y88b d88P  Y88b  888   8888b   888 d88P  Y88b
          888    888 888     888     888 Y88b.       888   88888b  888 888    888
          888        888     888     888  "Y888b.    888   888Y88b 888 888
          888        888     888     888     "Y88b.  888   888 Y88b888 888  88888
          888    888 888     888     888       "888  888   888  Y88888 888    888
          Y88b  d88P 888     Y88b. .d88P Y88b  d88P  888   888   Y8888 Y88b  d88P
           "Y8888P"  88888888 "Y88888P"   "Y8888P" 8888888 888    Y888  "Y8888P88
   */

  when(SHUTDOWN)(handleExceptions {
    case Event(c: CMD_FULFILL_HTLC, d: DATA_SHUTDOWN) =>
      Commitments.sendFulfill(d.data.commitments, c) match {
        case Right((commitments1, fulfill)) =>
          if (c.commit) self ! CMD_SIGN()
          handleCommandSuccess(c, d.modify(_.data.commitments).setTo(commitments1)) sending fulfill
        case Left(cause) =>
          // we acknowledge the command right away in case of failure
          handleCommandError(cause, c).acking(d.channelId, c)
      }

    case Event(fulfill: UpdateFulfillHtlc, d: DATA_SHUTDOWN) =>
      Commitments.receiveFulfill(d.data.commitments, fulfill) match {
        case Right((commitments1, origin, htlc)) =>
          // we forward preimages as soon as possible to the upstream channel because it allows us to pull funds
          relayer ! RES_ADD_SETTLED(origin, htlc, HtlcResult.RemoteFulfill(fulfill))
          stay() using d.modify(_.data.commitments).setTo(commitments1)
        case Left(cause) => handleLocalError(cause, Some(fulfill))
      }

    case Event(c: CMD_FAIL_HTLC, d: DATA_SHUTDOWN) =>
      Commitments.sendFail(d.data.commitments, c, nodeParams.privateKey) match {
        case Right((commitments1, fail)) =>
          if (c.commit) self ! CMD_SIGN()
          handleCommandSuccess(c, d.modify(_.data.commitments).setTo(commitments1)) sending fail
        case Left(cause) =>
          // we acknowledge the command right away in case of failure
          handleCommandError(cause, c).acking(d.channelId, c)
      }

    case Event(c: CMD_FAIL_MALFORMED_HTLC, d: DATA_SHUTDOWN) =>
      Commitments.sendFailMalformed(d.data.commitments, c) match {
        case Right((commitments1, fail)) =>
          if (c.commit) self ! CMD_SIGN()
          handleCommandSuccess(c, d.modify(_.data.commitments).setTo(commitments1)) sending fail
        case Left(cause) =>
          // we acknowledge the command right away in case of failure
          handleCommandError(cause, c).acking(d.channelId, c)
      }

    case Event(fail: UpdateFailHtlc, d: DATA_SHUTDOWN) =>
      Commitments.receiveFail(d.data.commitments, fail) match {
        case Right((commitments1, _, _)) =>
          stay() using d.modify(_.data.commitments).setTo(commitments1)
        case Left(cause) => handleLocalError(cause, Some(fail))
      }

    case Event(fail: UpdateFailMalformedHtlc, d: DATA_SHUTDOWN) =>
      Commitments.receiveFailMalformed(d.data.commitments, fail) match {
        case Right((commitments1, _, _)) => stay() using d.modify(_.data.commitments).setTo(commitments1)
        case Left(cause) => handleLocalError(cause, Some(fail))
      }

    case Event(c: CMD_UPDATE_FEE, d: DATA_SHUTDOWN) =>
      Commitments.sendFee(d.data.commitments, c, nodeParams.onChainFeeConf) match {
        case Right((commitments1, fee)) =>
          if (c.commit) self ! CMD_SIGN()
          handleCommandSuccess(c, d.modify(_.data.commitments).setTo(commitments1)) sending fee
        case Left(cause) => handleCommandError(cause, c)
      }

    case Event(fee: UpdateFee, d: DATA_SHUTDOWN) =>
      Commitments.receiveFee(d.data.commitments, fee, nodeParams.onChainFeeConf) match {
        case Right(commitments1) => stay() using d.modify(_.data.commitments).setTo(commitments1)
        case Left(cause) => handleLocalError(cause, Some(fee))
      }

    case Event(c: CMD_SIGN, d: DATA_SHUTDOWN) =>
      import d.data.commitments
      commitments.remoteNextCommitInfo match {
        case _ if !Commitments.localHasChanges(commitments) =>
          log.debug("ignoring CMD_SIGN (nothing to sign)")
          stay()
        case Right(_) =>
          Commitments.sendCommit(commitments, keyManager) match {
            case Right((commitments1, commit)) =>
              log.debug("sending a new sig, spec:\n{}", Commitments.specs2String(commitments1))
              val Left(waitingForRevocation) = commitments1.remoteNextCommitInfo
              val nextRemoteCommit = waitingForRevocation.nextRemoteCommit
              val nextCommitNumber = nextRemoteCommit.index
              // we persist htlc data in order to be able to claim htlc outputs in case a revoked tx is published by our
              // counterparty, so only htlcs above remote's dust_limit matter
              val trimmedHtlcs = Transactions.trimOfferedHtlcs(commitments.remoteParams.dustLimit, nextRemoteCommit.spec, commitments.commitmentFormat) ++
                Transactions.trimReceivedHtlcs(commitments.remoteParams.dustLimit, nextRemoteCommit.spec, commitments.commitmentFormat)
              trimmedHtlcs.map(_.add).foreach { htlc =>
                log.debug(s"adding paymentHash=${htlc.paymentHash} cltvExpiry=${htlc.cltvExpiry} to htlcs db for commitNumber=$nextCommitNumber")
                nodeParams.db.channels.addHtlcInfo(d.channelId, nextCommitNumber, htlc.paymentHash, htlc.cltvExpiry)
              }
              context.system.eventStream.publish(ChannelSignatureSent(self, commitments1))
              // we expect a quick response from our peer
              startSingleTimer(RevocationTimeout.toString, RevocationTimeout(commitments1.remoteCommit.index, peer), nodeParams.channelConf.revocationTimeout)
              handleCommandSuccess(c, d.modify(_.data.commitments).setTo(commitments1)).storing().sending(commit).acking(commitments1.localChanges.signed)
            case Left(cause) => handleCommandError(cause, c)
          }
        case Left(waitForRevocation) =>
          log.debug("already in the process of signing, will sign again as soon as possible")
          stay() using d.modify(_.data.commitments.remoteNextCommitInfo).setTo(Left(waitForRevocation.copy(reSignAsap = true)))
      }

    case Event(commit: CommitSig, d: DATA_SHUTDOWN) =>
      import d.data.{commitments, localShutdown, remoteShutdown}
      Commitments.receiveCommit(commitments, commit, keyManager) match {
        case Right((commitments1, revocation)) =>
          // we always reply with a revocation
          log.debug("received a new sig:\n{}", Commitments.specs2String(commitments1))
          context.system.eventStream.publish(ChannelSignatureReceived(self, commitments1))
          if (commitments1.hasNoPendingHtlcsOrFeeUpdate) {
            if (commitments.localParams.isFunder) {
              // we are funder, need to initiate the negotiation by sending the first closing_signed
              val (closingTx, closingSigned) = Closing.makeFirstClosingTx(keyManager, commitments1, localShutdown.scriptPubKey, remoteShutdown.scriptPubKey, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets, d.data.closingFeerates)
              goto(NEGOTIATING) using DATA_NEGOTIATING(ChannelData.Negotiating(commitments1, localShutdown, remoteShutdown, List(List(ClosingTxProposed(closingTx, closingSigned))), bestUnpublishedClosingTx_opt = None)) storing() sending revocation :: closingSigned :: Nil
            } else {
              // we are fundee, will wait for their closing_signed
              goto(NEGOTIATING) using DATA_NEGOTIATING(ChannelData.Negotiating(commitments1, localShutdown, remoteShutdown, closingTxProposed = List(List()), bestUnpublishedClosingTx_opt = None)) storing() sending revocation
            }
          } else {
            if (Commitments.localHasChanges(commitments1)) {
              // if we have newly acknowledged changes let's sign them
              self ! CMD_SIGN()
            }
            stay() using d.modify(_.data.commitments).setTo(commitments1) storing() sending revocation
          }
        case Left(cause) => handleLocalError(cause, Some(commit))
      }

    case Event(revocation: RevokeAndAck, d: DATA_SHUTDOWN) =>
      import d.data.{commitments, localShutdown, remoteShutdown}
      // we received a revocation because we sent a signature
      // => all our changes have been acked including the shutdown message
      Commitments.receiveRevocation(commitments, revocation, nodeParams.onChainFeeConf.feerateToleranceFor(remoteNodeId).dustTolerance.maxExposure) match {
        case Right((commitments1, actions)) =>
          cancelTimer(RevocationTimeout.toString)
          log.debug("received a new rev, spec:\n{}", Commitments.specs2String(commitments1))
          actions.foreach {
            case PostRevocationAction.RelayHtlc(add) =>
              // BOLT 2: A sending node SHOULD fail to route any HTLC added after it sent shutdown.
              log.debug("closing in progress: failing {}", add)
              self ! CMD_FAIL_HTLC(add.id, Right(PermanentChannelFailure), commit = true)
            case PostRevocationAction.RejectHtlc(add) =>
              // BOLT 2: A sending node SHOULD fail to route any HTLC added after it sent shutdown.
              log.debug("closing in progress: rejecting {}", add)
              self ! CMD_FAIL_HTLC(add.id, Right(PermanentChannelFailure), commit = true)
            case PostRevocationAction.RelayFailure(result) =>
              log.debug("forwarding {} to relayer", result)
              relayer ! result
          }
          if (commitments1.hasNoPendingHtlcsOrFeeUpdate) {
            log.debug("switching to NEGOTIATING spec:\n{}", Commitments.specs2String(commitments1))
            if (commitments.localParams.isFunder) {
              // we are funder, need to initiate the negotiation by sending the first closing_signed
              val (closingTx, closingSigned) = Closing.makeFirstClosingTx(keyManager, commitments1, localShutdown.scriptPubKey, remoteShutdown.scriptPubKey, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets, d.data.closingFeerates)
              goto(NEGOTIATING) using DATA_NEGOTIATING(ChannelData.Negotiating(commitments1, localShutdown, remoteShutdown, List(List(ClosingTxProposed(closingTx, closingSigned))), bestUnpublishedClosingTx_opt = None)) storing() sending closingSigned
            } else {
              // we are fundee, will wait for their closing_signed
              goto(NEGOTIATING) using DATA_NEGOTIATING(ChannelData.Negotiating(commitments1, localShutdown, remoteShutdown, closingTxProposed = List(List()), bestUnpublishedClosingTx_opt = None)) storing()
            }
          } else {
            if (Commitments.localHasChanges(commitments1) && commitments.remoteNextCommitInfo.left.map(_.reSignAsap) == Left(true)) {
              self ! CMD_SIGN()
            }
            stay() using d.modify(_.data.commitments).setTo(commitments1) storing()
          }
        case Left(cause) => handleLocalError(cause, Some(revocation))
      }

    case Event(r: RevocationTimeout, d: DATA_SHUTDOWN) => handleRevocationTimeout(r, d.data)

    case Event(ProcessCurrentBlockHeight(c), d: DATA_SHUTDOWN) => handleNewBlock(c, d.data)

    case Event(c: CurrentFeerates, d: DATA_SHUTDOWN) => handleCurrentFeerate(c, d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_SHUTDOWN) if tx.txid == d.data.commitments.remoteCommit.txid => handleRemoteSpentCurrent(tx, d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_SHUTDOWN) if d.data.commitments.remoteNextCommitInfo.left.toOption.exists(_.nextRemoteCommit.txid == tx.txid) => handleRemoteSpentNext(tx, d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_SHUTDOWN) => handleRemoteSpentOther(tx, d.data)

    case Event(c: CMD_CLOSE, d: DATA_SHUTDOWN) =>
      c.feerates match {
        case Some(feerates) if c.feerates != d.data.closingFeerates =>
          if (c.scriptPubKey.nonEmpty && !c.scriptPubKey.contains(d.data.localShutdown.scriptPubKey)) {
            log.warning("cannot update closing script when closing is already in progress")
            handleCommandError(ClosingAlreadyInProgress(d.channelId), c)
          } else {
            log.info("updating our closing feerates: {}", feerates)
            handleCommandSuccess(c, d.modify(_.data.closingFeerates).setTo(c.feerates)) storing()
          }
        case _ =>
          handleCommandError(ClosingAlreadyInProgress(d.channelId), c)
      }

    case Event(e: Error, _: DATA_SHUTDOWN) => handleRemoteError(e)

  })

  when(NEGOTIATING)(handleExceptions {
    // Upon reconnection, nodes must re-transmit their shutdown message, so we may receive it now.
    case Event(remoteShutdown: Shutdown, d: DATA_NEGOTIATING) =>
      if (remoteShutdown != d.data.remoteShutdown) {
        // This is a spec violation: it will likely lead to a disagreement when exchanging closing_signed and a force-close.
        log.warning("received unexpected shutdown={} (previous={})", remoteShutdown, d.data.remoteShutdown)
      }
      stay()

    case Event(c: ClosingSigned, d: DATA_NEGOTIATING) =>
      import d.data.{closingTxProposed, commitments, localShutdown, remoteShutdown}
      log.info("received closing fee={}", c.feeSatoshis)
      val (remoteClosingFee, remoteSig) = (c.feeSatoshis, c.signature)
      Closing.checkClosingSignature(keyManager, commitments, localShutdown.scriptPubKey, remoteShutdown.scriptPubKey, remoteClosingFee, remoteSig) match {
        case Right((signedClosingTx, closingSignedRemoteFees)) =>
          val lastLocalClosingSigned_opt = closingTxProposed.last.lastOption
          if (lastLocalClosingSigned_opt.exists(_.localClosingSigned.feeSatoshis == remoteClosingFee)) {
            // they accepted the last fee we sent them, so we close without sending a closing_signed
            handleMutualClose(signedClosingTx, Left(d.data.copy(bestUnpublishedClosingTx_opt = Some(signedClosingTx))))
          } else if (closingTxProposed.flatten.size >= MAX_NEGOTIATION_ITERATIONS) {
            // there were too many iterations, we stop negotiating and accept their fee
            log.warning("could not agree on closing fees after {} iterations, accepting their closing fees ({})", MAX_NEGOTIATION_ITERATIONS, remoteClosingFee)
            handleMutualClose(signedClosingTx, Left(d.data.copy(bestUnpublishedClosingTx_opt = Some(signedClosingTx)))) sending closingSignedRemoteFees
          } else if (lastLocalClosingSigned_opt.flatMap(_.localClosingSigned.feeRange_opt).exists(r => r.min <= remoteClosingFee && remoteClosingFee <= r.max)) {
            // they chose a fee inside our proposed fee range, so we close and send a closing_signed for that fee
            val localFeeRange = lastLocalClosingSigned_opt.flatMap(_.localClosingSigned.feeRange_opt).get
            log.info("they chose a closing fee={} within our fee range (min={} max={})", remoteClosingFee, localFeeRange.min, localFeeRange.max)
            handleMutualClose(signedClosingTx, Left(d.data.copy(bestUnpublishedClosingTx_opt = Some(signedClosingTx)))) sending closingSignedRemoteFees
          } else if (commitments.localCommit.spec.toLocal == 0.msat) {
            // we have nothing at stake so there is no need to negotiate, we accept their fee right away
            handleMutualClose(signedClosingTx, Left(d.data.copy(bestUnpublishedClosingTx_opt = Some(signedClosingTx)))) sending closingSignedRemoteFees
          } else {
            c.feeRange_opt match {
              case Some(ClosingSignedTlv.FeeRange(minFee, maxFee)) if !commitments.localParams.isFunder =>
                // if we are fundee and they proposed a fee range, we pick a value in that range and they should accept it without further negotiation
                // we don't care much about the closing fee since they're paying it (not us) and we can use CPFP if we want to speed up confirmation
                val localClosingFees = Closing.firstClosingFee(commitments, localShutdown.scriptPubKey, remoteShutdown.scriptPubKey, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets)
                if (maxFee < localClosingFees.min) {
                  log.warning("their highest closing fee is below our minimum fee: {} < {}", maxFee, localClosingFees.min)
                  stay() sending Warning(d.channelId, s"closing fee range must not be below ${localClosingFees.min}")
                } else {
                  val closingFee = localClosingFees match {
                    case ClosingFees(preferred, _, _) if preferred > maxFee => maxFee
                    // if we underestimate the fee, then we're happy with whatever they propose (it will confirm more quickly and we're not paying it)
                    case ClosingFees(preferred, _, _) if preferred < remoteClosingFee => remoteClosingFee
                    case ClosingFees(preferred, _, _) => preferred
                  }
                  if (closingFee == remoteClosingFee) {
                    log.info("accepting their closing fee={}", remoteClosingFee)
                    handleMutualClose(signedClosingTx, Left(d.data.copy(bestUnpublishedClosingTx_opt = Some(signedClosingTx)))) sending closingSignedRemoteFees
                  } else {
                    val (closingTx, closingSigned) = Closing.makeClosingTx(keyManager, commitments, localShutdown.scriptPubKey, remoteShutdown.scriptPubKey, ClosingFees(closingFee, minFee, maxFee))
                    log.info("proposing closing fee={} in their fee range (min={} max={})", closingSigned.feeSatoshis, minFee, maxFee)
                    val closingTxProposed1 = (closingTxProposed: @unchecked) match {
                      case previousNegotiations :+ currentNegotiation => previousNegotiations :+ (currentNegotiation :+ ClosingTxProposed(closingTx, closingSigned))
                    }
                    val d1 = d.modify(_.data.closingTxProposed).setTo(closingTxProposed1)
                      .modify(_.data.bestUnpublishedClosingTx_opt).setTo(Some(signedClosingTx))
                    stay() using d1 storing() sending closingSigned
                  }
                }
              case _ =>
                val lastLocalClosingFee_opt = lastLocalClosingSigned_opt.map(_.localClosingSigned.feeSatoshis)
                val (closingTx, closingSigned) = {
                  // if we are fundee and we were waiting for them to send their first closing_signed, we don't have a lastLocalClosingFee, so we compute a firstClosingFee
                  val localClosingFees = Closing.firstClosingFee(commitments, localShutdown.scriptPubKey, remoteShutdown.scriptPubKey, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets)
                  val nextPreferredFee = Closing.nextClosingFee(lastLocalClosingFee_opt.getOrElse(localClosingFees.preferred), remoteClosingFee)
                  Closing.makeClosingTx(keyManager, commitments, localShutdown.scriptPubKey, remoteShutdown.scriptPubKey, localClosingFees.copy(preferred = nextPreferredFee))
                }
                val closingTxProposed1 = (closingTxProposed: @unchecked) match {
                  case previousNegotiations :+ currentNegotiation => previousNegotiations :+ (currentNegotiation :+ ClosingTxProposed(closingTx, closingSigned))
                }
                if (lastLocalClosingFee_opt.contains(closingSigned.feeSatoshis)) {
                  // next computed fee is the same than the one we previously sent (probably because of rounding), let's close now
                  handleMutualClose(signedClosingTx, Left(d.data.copy(bestUnpublishedClosingTx_opt = Some(signedClosingTx))))
                } else if (closingSigned.feeSatoshis == remoteClosingFee) {
                  // we have converged!
                  log.info("accepting their closing fee={}", remoteClosingFee)
                  handleMutualClose(signedClosingTx, Left(d.data.copy(closingTxProposed = closingTxProposed1, bestUnpublishedClosingTx_opt = Some(signedClosingTx)))) sending closingSigned
                } else {
                  log.info("proposing closing fee={}", closingSigned.feeSatoshis)
                  val d1 = d.modify(_.data.closingTxProposed).setTo(closingTxProposed1)
                    .modify(_.data.bestUnpublishedClosingTx_opt).setTo(Some(signedClosingTx))
                  stay() using d1 storing() sending closingSigned
                }
            }
          }
        case Left(cause) => handleLocalError(cause, Some(c))
      }

    case Event(WatchFundingSpentTriggered(tx), d: DATA_NEGOTIATING) if d.data.closingTxProposed.flatten.exists(_.unsignedTx.tx.txid == tx.txid) =>
      // they can publish a closing tx with any sig we sent them, even if we are not done negotiating
      handleMutualClose(getMutualClosePublished(tx, d.data.closingTxProposed), Left(d.data))

    case Event(WatchFundingSpentTriggered(tx), d: DATA_NEGOTIATING) if d.data.bestUnpublishedClosingTx_opt.exists(_.tx.txid == tx.txid) =>
      log.warning(s"looks like a mutual close tx has been published from the outside of the channel: closingTxId=${tx.txid}")
      // if we were in the process of closing and already received a closing sig from the counterparty, it's always better to use that
      handleMutualClose(d.data.bestUnpublishedClosingTx_opt.get, Left(d.data))

    case Event(WatchFundingSpentTriggered(tx), d: DATA_NEGOTIATING) if tx.txid == d.data.commitments.remoteCommit.txid => handleRemoteSpentCurrent(tx, d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_NEGOTIATING) if d.data.commitments.remoteNextCommitInfo.left.toOption.exists(_.nextRemoteCommit.txid == tx.txid) => handleRemoteSpentNext(tx, d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_NEGOTIATING) => handleRemoteSpentOther(tx, d.data)

    case Event(c: CMD_CLOSE, d: DATA_NEGOTIATING) =>
      import d.data.{closingTxProposed, commitments, localShutdown, remoteShutdown}
      c.feerates match {
        case Some(feerates) =>
          if (c.scriptPubKey.nonEmpty && !c.scriptPubKey.contains(localShutdown.scriptPubKey)) {
            log.warning("cannot update closing script when closing is already in progress")
            handleCommandError(ClosingAlreadyInProgress(d.channelId), c)
          } else {
            log.info("updating our closing feerates: {}", feerates)
            val (closingTx, closingSigned) = Closing.makeFirstClosingTx(keyManager, commitments, localShutdown.scriptPubKey, remoteShutdown.scriptPubKey, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets, Some(feerates))
            val closingTxProposed1 = closingTxProposed match {
              case previousNegotiations :+ currentNegotiation => previousNegotiations :+ (currentNegotiation :+ ClosingTxProposed(closingTx, closingSigned))
              case previousNegotiations => previousNegotiations :+ List(ClosingTxProposed(closingTx, closingSigned))
            }
            handleCommandSuccess(c, d.modify(_.data.closingTxProposed).setTo(closingTxProposed1)) storing() sending closingSigned
          }
        case _ =>
          handleCommandError(ClosingAlreadyInProgress(d.channelId), c)
      }

    case Event(e: Error, _: DATA_NEGOTIATING) => handleRemoteError(e)

  })

  when(CLOSING)(handleExceptions {
    case Event(c: CMD_FULFILL_HTLC, d: DATA_CLOSING) =>
      import d.data.{commitments, localCommitPublished, nextRemoteCommitPublished, remoteCommitPublished}
      Commitments.sendFulfill(commitments, c) match {
        case Right((commitments1, _)) =>
          log.info("got valid payment preimage, recalculating transactions to redeem the corresponding htlc on-chain")
          val localCommitPublished1 = localCommitPublished.map(localCommitPublished => Helpers.Closing.claimCurrentLocalCommitTxOutputs(keyManager, commitments1, localCommitPublished.commitTx, nodeParams.currentBlockHeight, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets))
          val remoteCommitPublished1 = remoteCommitPublished.map(remoteCommitPublished => Helpers.Closing.claimRemoteCommitTxOutputs(keyManager, commitments1, commitments1.remoteCommit, remoteCommitPublished.commitTx, nodeParams.currentBlockHeight, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets))
          val nextRemoteCommitPublished1 = nextRemoteCommitPublished.map(remoteCommitPublished => {
            require(commitments1.remoteNextCommitInfo.isLeft, "next remote commit must be defined")
            val remoteCommit = commitments1.remoteNextCommitInfo.swap.toOption.get.nextRemoteCommit
            Helpers.Closing.claimRemoteCommitTxOutputs(keyManager, commitments1, remoteCommit, remoteCommitPublished.commitTx, nodeParams.currentBlockHeight, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets)
          })

          def republish(): Unit = {
            localCommitPublished1.foreach(lcp => doPublish(lcp, commitments1))
            remoteCommitPublished1.foreach(rcp => doPublish(rcp, commitments1))
            nextRemoteCommitPublished1.foreach(rcp => doPublish(rcp, commitments1))
          }

          val d1 = d.modify(_.data.commitments).setTo(commitments1)
            .modify(_.data.localCommitPublished).setTo(localCommitPublished1)
            .modify(_.data.remoteCommitPublished).setTo(remoteCommitPublished1)
            .modify(_.data.nextRemoteCommitPublished).setTo(nextRemoteCommitPublished1)
          handleCommandSuccess(c, d1) storing() calling republish()
        case Left(cause) => handleCommandError(cause, c)
      }

    case Event(getTxResponse: GetTxWithMetaResponse, d: DATA_CLOSING) if getTxResponse.txid == d.data.commitments.commitInput.outPoint.txid =>
      // NB: waitingSinceBlock contains the block at which closing was initiated, not the block at which funding was initiated.
      // That means we're lenient with our peer and give its funding tx more time to confirm, to avoid having to store two distinct
      // waitingSinceBlock (e.g. closingWaitingSinceBlock and fundingWaitingSinceBlock).
      handleGetFundingTx(getTxResponse, d.data.waitingSince, d.data.fundingTx)

    case Event(BITCOIN_FUNDING_PUBLISH_FAILED, d: DATA_CLOSING) => handleFundingPublishFailed(d.data)

    case Event(BITCOIN_FUNDING_TIMEOUT, d: DATA_CLOSING) => handleFundingTimeout(d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_CLOSING) =>
      if (d.data.mutualClosePublished.exists(_.tx.txid == tx.txid)) {
        // we already know about this tx, probably because we have published it ourselves after successful negotiation
        stay()
      } else if (d.data.mutualCloseProposed.exists(_.tx.txid == tx.txid)) {
        // at any time they can publish a closing tx with any sig we sent them: we use their version since it has their sig as well
        val closingTx = d.data.mutualCloseProposed.find(_.tx.txid == tx.txid).get.copy(tx = tx)
        handleMutualClose(closingTx, Right(d.data))
      } else if (d.data.localCommitPublished.exists(_.commitTx.txid == tx.txid)) {
        // this is because WatchSpent watches never expire and we are notified multiple times
        stay()
      } else if (d.data.remoteCommitPublished.exists(_.commitTx.txid == tx.txid)) {
        // this is because WatchSpent watches never expire and we are notified multiple times
        stay()
      } else if (d.data.nextRemoteCommitPublished.exists(_.commitTx.txid == tx.txid)) {
        // this is because WatchSpent watches never expire and we are notified multiple times
        stay()
      } else if (d.data.futureRemoteCommitPublished.exists(_.commitTx.txid == tx.txid)) {
        // this is because WatchSpent watches never expire and we are notified multiple times
        stay()
      } else if (tx.txid == d.data.commitments.remoteCommit.txid) {
        // counterparty may attempt to spend its last commit tx at any time
        handleRemoteSpentCurrent(tx, d.data)
      } else if (d.data.commitments.remoteNextCommitInfo.left.toOption.exists(_.nextRemoteCommit.txid == tx.txid)) {
        // counterparty may attempt to spend its last commit tx at any time
        handleRemoteSpentNext(tx, d.data)
      } else {
        // counterparty may attempt to spend a revoked commit tx at any time
        handleRemoteSpentOther(tx, d.data)
      }

    case Event(WatchOutputSpentTriggered(tx), d: DATA_CLOSING) =>
      import d.data.{commitments, revokedCommitPublished}
      // one of the outputs of the local/remote/revoked commit was spent
      // we just put a watch to be notified when it is confirmed
      blockchain ! WatchTxConfirmed(self, tx.txid, nodeParams.channelConf.minDepthBlocks)
      // when a remote or local commitment tx containing outgoing htlcs is published on the network,
      // we watch it in order to extract payment preimage if funds are pulled by the counterparty
      // we can then use these preimages to fulfill origin htlcs
      log.info(s"processing bitcoin output spent by txid=${tx.txid} tx=$tx")
      val extracted = Closing.extractPreimages(commitments.localCommit, tx)
      extracted.foreach { case (htlc, preimage) =>
        commitments.originChannels.get(htlc.id) match {
          case Some(origin) =>
            log.info(s"fulfilling htlc #${htlc.id} paymentHash=${htlc.paymentHash} origin=$origin")
            relayer ! RES_ADD_SETTLED(origin, htlc, HtlcResult.OnChainFulfill(preimage))
          case None =>
            // if we don't have the origin, it means that we already have forwarded the fulfill so that's not a big deal.
            // this can happen if they send a signature containing the fulfill, then fail the channel before we have time to sign it
            log.info(s"cannot fulfill htlc #${htlc.id} paymentHash=${htlc.paymentHash} (origin not found)")
        }
      }
      val revokedCommitPublished1 = revokedCommitPublished.map { rev =>
        val (rev1, penaltyTxs) = Closing.claimRevokedHtlcTxOutputs(keyManager, commitments, rev, tx, nodeParams.onChainFeeConf.feeEstimator)
        penaltyTxs.foreach(claimTx => txPublisher ! PublishFinalTx(claimTx, claimTx.fee, None))
        penaltyTxs.foreach(claimTx => blockchain ! WatchOutputSpent(self, tx.txid, claimTx.input.outPoint.index.toInt, hints = Set(claimTx.tx.txid)))
        rev1
      }
      stay() using d.modify(_.data.revokedCommitPublished).setTo(revokedCommitPublished1) storing()

    case Event(WatchTxConfirmedTriggered(blockHeight, _, tx), d: DATA_CLOSING) =>
      import d.data.commitments
      log.info(s"txid=${tx.txid} has reached mindepth, updating closing state")
      context.system.eventStream.publish(TransactionConfirmed(d.channelId, remoteNodeId, tx))
      // first we check if this tx belongs to one of the current local/remote commits, update it and update the channel data
      val closing1 = d.data.copy(
        localCommitPublished = d.data.localCommitPublished.map(localCommitPublished => {
          // If the tx is one of our HTLC txs, we now publish a 3rd-stage claim-htlc-tx that claims its output.
          val (localCommitPublished1, claimHtlcTx_opt) = Closing.claimLocalCommitHtlcTxOutput(localCommitPublished, keyManager, commitments, tx, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets)
          claimHtlcTx_opt.foreach(claimHtlcTx => {
            txPublisher ! PublishFinalTx(claimHtlcTx, claimHtlcTx.fee, None)
            blockchain ! WatchTxConfirmed(self, claimHtlcTx.tx.txid, nodeParams.channelConf.minDepthBlocks)
          })
          Closing.updateLocalCommitPublished(localCommitPublished1, tx)
        }),
        remoteCommitPublished = d.data.remoteCommitPublished.map(Closing.updateRemoteCommitPublished(_, tx)),
        nextRemoteCommitPublished = d.data.nextRemoteCommitPublished.map(Closing.updateRemoteCommitPublished(_, tx)),
        futureRemoteCommitPublished = d.data.futureRemoteCommitPublished.map(Closing.updateRemoteCommitPublished(_, tx)),
        revokedCommitPublished = d.data.revokedCommitPublished.map(Closing.updateRevokedCommitPublished(_, tx))
      )
      // if the local commitment tx just got confirmed, let's send an event telling when we will get the main output refund
      if (closing1.localCommitPublished.exists(_.commitTx.txid == tx.txid)) {
        context.system.eventStream.publish(LocalCommitConfirmed(self, remoteNodeId, d.channelId, blockHeight + commitments.remoteParams.toSelfDelay.toInt))
      }
      // we may need to fail some htlcs in case a commitment tx was published and they have reached the timeout threshold
      val timedOutHtlcs = Closing.isClosingTypeAlreadyKnown(closing1) match {
        case Some(c: Closing.LocalClose) => Closing.trimmedOrTimedOutHtlcs(commitments.commitmentFormat, c.localCommit, c.localCommitPublished, commitments.localParams.dustLimit, tx)
        case Some(c: Closing.RemoteClose) => Closing.trimmedOrTimedOutHtlcs(commitments.commitmentFormat, c.remoteCommit, c.remoteCommitPublished, commitments.remoteParams.dustLimit, tx)
        case _ => Set.empty[UpdateAddHtlc] // we lose htlc outputs in dataloss protection scenarios (future remote commit)
      }
      timedOutHtlcs.foreach { add =>
        commitments.originChannels.get(add.id) match {
          case Some(origin) =>
            log.info(s"failing htlc #${add.id} paymentHash=${add.paymentHash} origin=$origin: htlc timed out")
            relayer ! RES_ADD_SETTLED(origin, add, HtlcResult.OnChainFail(HtlcsTimedoutDownstream(d.channelId, Set(add))))
          case None =>
            // same as for fulfilling the htlc (no big deal)
            log.info(s"cannot fail timed out htlc #${add.id} paymentHash=${add.paymentHash} (origin not found)")
        }
      }
      // we also need to fail outgoing htlcs that we know will never reach the blockchain
      Closing.overriddenOutgoingHtlcs(d.data, tx).foreach { add =>
        commitments.originChannels.get(add.id) match {
          case Some(origin) =>
            log.info(s"failing htlc #${add.id} paymentHash=${add.paymentHash} origin=$origin: overridden by local commit")
            relayer ! RES_ADD_SETTLED(origin, add, HtlcResult.OnChainFail(HtlcOverriddenByLocalCommit(d.channelId, add)))
          case None =>
            // same as for fulfilling the htlc (no big deal)
            log.info(s"cannot fail overridden htlc #${add.id} paymentHash=${add.paymentHash} (origin not found)")
        }
      }
      // for our outgoing payments, let's send events if we know that they will settle on chain
      Closing
        .onChainOutgoingHtlcs(commitments.localCommit, commitments.remoteCommit, commitments.remoteNextCommitInfo.left.toOption.map(_.nextRemoteCommit), tx)
        .map(add => (add, commitments.originChannels.get(add.id).collect { case o: Origin.Local => o.id })) // we resolve the payment id if this was a local payment
        .collect { case (add, Some(id)) => context.system.eventStream.publish(PaymentSettlingOnChain(id, amount = add.amountMsat, add.paymentHash)) }
      // then let's see if any of the possible close scenarios can be considered done
      val closingType_opt = Closing.isClosed(closing1, Some(tx))
      // finally, if one of the unilateral closes is done, we move to CLOSED state, otherwise we stay() (note that we don't store the state)
      closingType_opt match {
        case Some(closingType) =>
          log.info(s"channel closed (type=${closingType_opt.map(c => EventType.Closed(c).label).getOrElse("UnknownYet")})")
          context.system.eventStream.publish(ChannelClosed(self, d.channelId, closingType, commitments))
          goto(CLOSED) using DATA_CLOSED(Some(closing1)) storing()
        case None =>
          stay() using DATA_CLOSING(closing1) storing()
      }

    case Event(_: ChannelReestablish, d: DATA_CLOSING) =>
      // they haven't detected that we were closing and are trying to reestablish a connection
      // we give them one of the published txes as a hint
      // note spendingTx != Nil (that's a requirement of DATA_CLOSING)
      val exc = FundingTxSpent(d.channelId, d.data.spendingTxs.head)
      val error = Error(d.channelId, exc.getMessage)
      stay() sending error

    case Event(c: CMD_CLOSE, d: DATA_CLOSING) => handleCommandError(ClosingAlreadyInProgress(d.channelId), c)

    case Event(e: Error, _: DATA_CLOSING) => handleRemoteError(e)

    case Event(INPUT_DISCONNECTED | INPUT_RECONNECTED(_, _, _), _) => stay() // we don't really care at this point
  })

  when(CLOSED)(handleExceptions {
    case Event(Symbol("shutdown"), DATA_CLOSED(data_opt)) =>
      data_opt match {
        case Some(d) =>
          log.info(s"deleting database record for channelId=${d.channelId}")
          nodeParams.db.channels.removeChannel(d.channelId)
        case _ =>
      }
      log.info("shutting down")
      stop(FSM.Normal)

    case Event(MakeFundingTxResponse(fundingTx, _, _), _) =>
      // this may happen if connection is lost, or remote sends an error while we were waiting for the funding tx to be created by our wallet
      // in that case we rollback the tx
      wallet.rollback(fundingTx)
      stay()

    case Event(INPUT_DISCONNECTED, _) => stay() // we are disconnected, but it doesn't matter anymore
  })

  when(OFFLINE)(handleExceptions {
    case Event(INPUT_RECONNECTED(r, localInit, remoteInit), DATA_OFFLINE(d: ChannelData.WaitingForRemotePublishFutureCommitment)) =>
      activeConnection = r
      // they already proved that we have an outdated commitment
      // there isn't much to do except asking them again to publish their current commitment by sending an error
      val exc = PleasePublishYourCommitment(d.channelId)
      val error = Error(d.channelId, exc.getMessage)
      val d1 = d.copy(commitments = Helpers.updateFeatures(d, localInit, remoteInit).commitments)
      goto(WAIT_FOR_REMOTE_PUBLISH_FUTURE_COMMITMENT) using DATA_WAIT_FOR_REMOTE_PUBLISH_FUTURE_COMMITMENT(d1) sending error

    case Event(INPUT_RECONNECTED(r, localInit, remoteInit), DATA_OFFLINE(d)) =>
      activeConnection = r

      val yourLastPerCommitmentSecret = d.commitments.remotePerCommitmentSecrets.lastIndex.flatMap(d.commitments.remotePerCommitmentSecrets.getHash).getOrElse(ByteVector32.Zeroes)
      val channelKeyPath = keyManager.keyPath(d.commitments.localParams, d.commitments.channelConfig)
      val myCurrentPerCommitmentPoint = keyManager.commitmentPoint(channelKeyPath, d.commitments.localCommit.index)

      val channelReestablish = ChannelReestablish(
        channelId = d.channelId,
        nextLocalCommitmentNumber = d.commitments.localCommit.index + 1,
        nextRemoteRevocationNumber = d.commitments.remoteCommit.index,
        yourLastPerCommitmentSecret = PrivateKey(yourLastPerCommitmentSecret),
        myCurrentPerCommitmentPoint = myCurrentPerCommitmentPoint
      )

      // we update local/remote connection-local global/local features, we don't persist it right now
      val d1 = Helpers.updateFeatures(d, localInit, remoteInit)

      goto(SYNCING) using DATA_SYNCING(d1) sending channelReestablish

    // note: this can only happen if state is NORMAL or SHUTDOWN
    // -> in NEGOTIATING there are no more htlcs
    // -> in CLOSING we either have mutual closed (so no more htlcs), or already have unilaterally closed (so no action required), and we can't be in OFFLINE state anyway
    case Event(ProcessCurrentBlockHeight(c), d: DATA_OFFLINE) => handleNewBlock(c, d.data)

    case Event(c: CurrentFeerates, d: DATA_OFFLINE) => handleCurrentFeerateDisconnected(c, d.data)

    case Event(c: CMD_ADD_HTLC, DATA_OFFLINE(d: ChannelData.Normal)) => handleAddDisconnected(c, d)

    case Event(c: CMD_UPDATE_RELAY_FEE, DATA_OFFLINE(d: ChannelData.Normal)) => handleUpdateRelayFeeDisconnected(c, d)

    case Event(getTxResponse: GetTxWithMetaResponse, DATA_OFFLINE(d: ChannelData.WaitingForFundingConfirmed)) if getTxResponse.txid == d.commitments.commitInput.outPoint.txid => handleGetFundingTx(getTxResponse, d.waitingSince, d.fundingTx)

    case Event(BITCOIN_FUNDING_PUBLISH_FAILED, DATA_OFFLINE(d: ChannelData.WaitingForFundingConfirmed)) => handleFundingPublishFailed(d)

    case Event(BITCOIN_FUNDING_TIMEOUT, DATA_OFFLINE(d: ChannelData.WaitingForFundingConfirmed)) => handleFundingTimeout(d)

    // just ignore this, we will put a new watch when we reconnect, and we'll be notified again
    case Event(WatchFundingConfirmedTriggered(_, _, _), _) => stay()

    case Event(WatchFundingDeeplyBuriedTriggered(_, _, _), _) => stay()

    case Event(WatchFundingSpentTriggered(tx), DATA_OFFLINE(d: ChannelData.Negotiating)) if d.closingTxProposed.flatten.exists(_.unsignedTx.tx.txid == tx.txid) =>
      handleMutualClose(getMutualClosePublished(tx, d.closingTxProposed), Left(d))

    case Event(WatchFundingSpentTriggered(tx), d: DATA_OFFLINE) if tx.txid == d.data.commitments.remoteCommit.txid => handleRemoteSpentCurrent(tx, d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_OFFLINE) if d.data.commitments.remoteNextCommitInfo.left.toOption.exists(_.nextRemoteCommit.txid == tx.txid) => handleRemoteSpentNext(tx, d.data)

    case Event(WatchFundingSpentTriggered(tx), DATA_OFFLINE(d: ChannelData.WaitingForRemotePublishFutureCommitment)) => handleRemoteSpentFuture(tx, d)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_OFFLINE) => handleRemoteSpentOther(tx, d.data)

  })

  when(SYNCING)(handleExceptions {
    case Event(_: ChannelReestablish, DATA_SYNCING(d: ChannelData.WaitingForFundingConfirmed)) =>
      val minDepth = if (d.commitments.localParams.isFunder) {
        nodeParams.channelConf.minDepthBlocks
      } else {
        // when we're fundee we scale the min_depth confirmations depending on the funding amount
        Helpers.minDepthForFunding(nodeParams.channelConf, d.commitments.commitInput.txOut.amount)
      }
      // we put back the watch (operation is idempotent) because the event may have been fired while we were in OFFLINE
      blockchain ! WatchFundingConfirmed(self, d.commitments.commitInput.outPoint.txid, minDepth)
      goto(WAIT_FOR_FUNDING_CONFIRMED) using DATA_WAIT_FOR_FUNDING_CONFIRMED(d)

    case Event(_: ChannelReestablish, DATA_SYNCING(d: ChannelData.WaitingForFundingLocked)) =>
      log.debug("re-sending fundingLocked")
      val channelKeyPath = keyManager.keyPath(d.commitments.localParams, d.commitments.channelConfig)
      val nextPerCommitmentPoint = keyManager.commitmentPoint(channelKeyPath, 1)
      val fundingLocked = FundingLocked(d.commitments.channelId, nextPerCommitmentPoint)
      goto(WAIT_FOR_FUNDING_LOCKED) using DATA_WAIT_FOR_FUNDING_LOCKED(d) sending fundingLocked

    case Event(channelReestablish: ChannelReestablish, DATA_SYNCING(d: ChannelData.Normal)) =>
      Syncing.checkSync(keyManager, d, channelReestablish) match {
        case syncFailure: SyncResult.Failure =>
          handleSyncFailure(channelReestablish, syncFailure, d)
        case syncSuccess: SyncResult.Success =>
          var sendQueue = Queue.empty[LightningMessage]
          // normal case, our data is up-to-date

          if (channelReestablish.nextLocalCommitmentNumber == 1 && d.commitments.localCommit.index == 0) {
            // If next_local_commitment_number is 1 in both the channel_reestablish it sent and received, then the node MUST retransmit funding_locked, otherwise it MUST NOT
            log.debug("re-sending fundingLocked")
            val channelKeyPath = keyManager.keyPath(d.commitments.localParams, d.commitments.channelConfig)
            val nextPerCommitmentPoint = keyManager.commitmentPoint(channelKeyPath, 1)
            val fundingLocked = FundingLocked(d.commitments.channelId, nextPerCommitmentPoint)
            sendQueue = sendQueue :+ fundingLocked
          }

          // we may need to retransmit updates and/or commit_sig and/or revocation
          sendQueue = sendQueue ++ syncSuccess.retransmit

          // then we clean up unsigned updates
          val commitments1 = Commitments.discardUnsignedUpdates(d.commitments)

          commitments1.remoteNextCommitInfo match {
            case Left(_) =>
              // we expect them to (re-)send the revocation immediately
              startSingleTimer(RevocationTimeout.toString, RevocationTimeout(commitments1.remoteCommit.index, peer), nodeParams.channelConf.revocationTimeout)
            case _ => ()
          }

          // do I have something to sign?
          if (Commitments.localHasChanges(commitments1)) {
            self ! CMD_SIGN()
          }

          // BOLT 2: A node if it has sent a previous shutdown MUST retransmit shutdown.
          d.localShutdown.foreach {
            localShutdown =>
              log.debug("re-sending localShutdown")
              sendQueue = sendQueue :+ localShutdown
          }

          if (!d.buried) {
            // even if we were just disconnected/reconnected, we need to put back the watch because the event may have been
            // fired while we were in OFFLINE (if not, the operation is idempotent anyway)
            blockchain ! WatchFundingDeeplyBuried(self, d.commitments.commitInput.outPoint.txid, ANNOUNCEMENTS_MINCONF)
          } else {
            // channel has been buried enough, should we (re)send our announcement sigs?
            d.channelAnnouncement match {
              case None if !d.commitments.announceChannel =>
                // that's a private channel, nothing to do
                ()
              case None =>
                // BOLT 7: a node SHOULD retransmit the announcement_signatures message if it has not received an announcement_signatures message
                val localAnnSigs = Helpers.makeAnnouncementSignatures(nodeParams, d.commitments, d.shortChannelId)
                sendQueue = sendQueue :+ localAnnSigs
              case Some(_) =>
                // channel was already announced, nothing to do
                ()
            }
          }

          if (d.commitments.announceChannel) {
            // we will re-enable the channel after some delay to prevent flappy updates in case the connection is unstable
            startSingleTimer(Reconnected.toString, BroadcastChannelUpdate(Reconnected), 10 seconds)
          } else {
            // except for private channels where our peer is likely a mobile wallet: they will stay online only for a short period of time,
            // so we need to re-enable them immediately to ensure we can route payments to them. It's also less of a problem to frequently
            // refresh the channel update for private channels, since we won't broadcast it to the rest of the network.
            self ! BroadcastChannelUpdate(Reconnected)
          }

          // We usually handle feerate updates once per block (~10 minutes), but when our remote is a mobile wallet that
          // only briefly connects and then disconnects, we may never have the opportunity to send our `update_fee`, so
          // we send it (if needed) when reconnected.
          val shutdownInProgress = d.localShutdown.nonEmpty || d.remoteShutdown.nonEmpty
          if (d.commitments.localParams.isFunder && !shutdownInProgress) {
            val currentFeeratePerKw = d.commitments.localCommit.spec.commitTxFeerate
            val networkFeeratePerKw = nodeParams.onChainFeeConf.getCommitmentFeerate(remoteNodeId, d.commitments.channelType, d.commitments.capacity, None)
            if (nodeParams.onChainFeeConf.shouldUpdateFee(currentFeeratePerKw, networkFeeratePerKw)) {
              self ! CMD_UPDATE_FEE(networkFeeratePerKw, commit = true)
            }
          }

          goto(NORMAL) using DATA_NORMAL(d.copy(commitments = commitments1)) sending sendQueue
      }

    case Event(c: CMD_ADD_HTLC, DATA_SYNCING(d: ChannelData.Normal)) => handleAddDisconnected(c, d)

    case Event(channelReestablish: ChannelReestablish, DATA_SYNCING(d: ChannelData.ShuttingDown)) =>
      Syncing.checkSync(keyManager, d, channelReestablish) match {
        case syncFailure: SyncResult.Failure =>
          handleSyncFailure(channelReestablish, syncFailure, d)
        case syncSuccess: SyncResult.Success =>
          val commitments1 = Commitments.discardUnsignedUpdates(d.commitments)
          val sendQueue = Queue.empty[LightningMessage] ++ syncSuccess.retransmit :+ d.localShutdown
          // BOLT 2: A node if it has sent a previous shutdown MUST retransmit shutdown.
          goto(SHUTDOWN) using DATA_SHUTDOWN(d.copy(commitments = commitments1)) sending sendQueue
      }

    case Event(_: ChannelReestablish, DATA_SYNCING(d: ChannelData.Negotiating)) =>
      // BOLT 2: A node if it has sent a previous shutdown MUST retransmit shutdown.
      // negotiation restarts from the beginning, and is initialized by the funder
      // note: in any case we still need to keep all previously sent closing_signed, because they may publish one of them
      if (d.commitments.localParams.isFunder) {
        // we could use the last closing_signed we sent, but network fees may have changed while we were offline so it is better to restart from scratch
        val (closingTx, closingSigned) = Closing.makeFirstClosingTx(keyManager, d.commitments, d.localShutdown.scriptPubKey, d.remoteShutdown.scriptPubKey, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets, None)
        val closingTxProposed1 = d.closingTxProposed :+ List(ClosingTxProposed(closingTx, closingSigned))
        goto(NEGOTIATING) using DATA_NEGOTIATING(d.copy(closingTxProposed = closingTxProposed1)) storing() sending d.localShutdown :: closingSigned :: Nil
      } else {
        // we start a new round of negotiation
        val closingTxProposed1 = if (d.closingTxProposed.last.isEmpty) d.closingTxProposed else d.closingTxProposed :+ List()
        goto(NEGOTIATING) using DATA_NEGOTIATING(d.copy(closingTxProposed = closingTxProposed1)) sending d.localShutdown
      }

    // This handler is a workaround for an issue in lnd: starting with versions 0.10 / 0.11, they sometimes fail to send
    // a channel_reestablish when reconnecting a channel that recently got confirmed, and instead send a funding_locked
    // first and then go silent. This is due to a race condition on their side, so we trigger a reconnection, hoping that
    // we will eventually receive their channel_reestablish.
    case Event(_: FundingLocked, d) =>
      log.warning("received funding_locked before channel_reestablish (known lnd bug): disconnecting...")
      // NB: we use a small delay to ensure we've sent our warning before disconnecting.
      context.system.scheduler.scheduleOnce(2 second, peer, Peer.Disconnect(remoteNodeId))
      stay() sending Warning(d.channelId, "spec violation: you sent funding_locked before channel_reestablish")

    // This handler is a workaround for an issue in lnd similar to the one above: they sometimes send announcement_signatures
    // before channel_reestablish, which is a minor spec violation. It doesn't halt the channel, we can simply postpone
    // that message.
    case Event(remoteAnnSigs: AnnouncementSignatures, d) =>
      log.warning("received announcement_signatures before channel_reestablish (known lnd bug): delaying...")
      context.system.scheduler.scheduleOnce(5 seconds, self, remoteAnnSigs)
      stay() sending Warning(d.channelId, "spec violation: you sent announcement_signatures before channel_reestablish")

    case Event(ProcessCurrentBlockHeight(c), d: DATA_SYNCING) => handleNewBlock(c, d.data)

    case Event(c: CurrentFeerates, d: DATA_SYNCING) => handleCurrentFeerateDisconnected(c, d.data)

    case Event(getTxResponse: GetTxWithMetaResponse, DATA_SYNCING(d: ChannelData.WaitingForFundingConfirmed)) if getTxResponse.txid == d.commitments.commitInput.outPoint.txid => handleGetFundingTx(getTxResponse, d.waitingSince, d.fundingTx)

    case Event(BITCOIN_FUNDING_PUBLISH_FAILED, DATA_SYNCING(d: ChannelData.WaitingForFundingConfirmed)) => handleFundingPublishFailed(d)

    case Event(BITCOIN_FUNDING_TIMEOUT, DATA_SYNCING(d: ChannelData.WaitingForFundingConfirmed)) => handleFundingTimeout(d)

    // just ignore this, we will put a new watch when we reconnect, and we'll be notified again
    case Event(WatchFundingConfirmedTriggered(_, _, _), _) => stay()

    case Event(WatchFundingDeeplyBuriedTriggered(_, _, _), _) => stay()

    case Event(WatchFundingSpentTriggered(tx), DATA_SYNCING(d: ChannelData.Negotiating)) if d.closingTxProposed.flatten.exists(_.unsignedTx.tx.txid == tx.txid) =>
      handleMutualClose(getMutualClosePublished(tx, d.closingTxProposed), Left(d))

    case Event(WatchFundingSpentTriggered(tx), d: DATA_SYNCING) if tx.txid == d.data.commitments.remoteCommit.txid => handleRemoteSpentCurrent(tx, d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_SYNCING) if d.data.commitments.remoteNextCommitInfo.left.toOption.exists(_.nextRemoteCommit.txid == tx.txid) => handleRemoteSpentNext(tx, d.data)

    case Event(WatchFundingSpentTriggered(tx), d: DATA_SYNCING) => handleRemoteSpentOther(tx, d.data)

    case Event(e: Error, _) => handleRemoteError(e)
  })

  when(WAIT_FOR_REMOTE_PUBLISH_FUTURE_COMMITMENT)(handleExceptions {
    case Event(WatchFundingSpentTriggered(tx), d: DATA_WAIT_FOR_REMOTE_PUBLISH_FUTURE_COMMITMENT) => handleRemoteSpentFuture(tx, d.data)
  })

  when(ERR_INFORMATION_LEAK) {
    case Event(Symbol("nevermatches"), _) => stay() // we can't define a state with no event handler, so we put a dummy one here
  }

  whenUnhandled {

    case Event(INPUT_DISCONNECTED, d) if d.channelData().nonEmpty => goto(OFFLINE) using DATA_OFFLINE(d.channelData().get)

    case Event(c: CMD_GET_CHANNEL_STATE, _) =>
      val replyTo = if (c.replyTo == ActorRef.noSender) sender() else c.replyTo
      replyTo ! RES_GET_CHANNEL_STATE(stateName)
      stay()

    case Event(c: CMD_GET_CHANNEL_DATA, d) =>
      val replyTo = if (c.replyTo == ActorRef.noSender) sender() else c.replyTo
      replyTo ! RES_GET_CHANNEL_DATA(stateName, d.channelData())
      stay()

    case Event(c: CMD_GET_CHANNEL_INFO, d) =>
      val replyTo = if (c.replyTo == ActorRef.noSender) sender() else c.replyTo
      replyTo ! RES_GET_CHANNEL_INFO(remoteNodeId, d.channelId, stateName, d.channelData())
      stay()

    case Event(c: CMD_ADD_HTLC, d) =>
      log.info(s"rejecting htlc request in state=$stateName")
      val error = ChannelUnavailable(d.channelId)
      handleAddHtlcCommandError(c, error, None) // we don't provide a channel_update: this will be a permanent channel failure

    case Event(c: CMD_CLOSE, d) => handleCommandError(CommandUnavailableInThisState(d.channelId, "close", stateName), c)

    case Event(c: CMD_FORCECLOSE, d) =>
      d.channelData() match {
        case Some(data) =>
          val replyTo = if (c.replyTo == ActorRef.noSender) sender() else c.replyTo
          replyTo ! RES_SUCCESS(c, data.channelId)
          val failure = ForcedLocalCommit(data.channelId)
          handleLocalError(failure, Some(c))
        case _ => handleCommandError(CommandUnavailableInThisState(d.channelId, "forceclose", stateName), c)
      }

    // In states where we don't explicitly handle this command, we won't broadcast a new channel update immediately,
    // but we will once we get back to NORMAL, because the updated fees have been saved to our peers DB.
    case Event(c: CMD_UPDATE_RELAY_FEE, d) =>
      val replyTo = if (c.replyTo == ActorRef.noSender) sender() else c.replyTo
      replyTo ! RES_SUCCESS(c, d.channelId)
      stay()

    // at restore, if the configuration has changed, the channel will send a command to itself to update the relay fees
    case Event(RES_SUCCESS(_: CMD_UPDATE_RELAY_FEE, channelId), d: DATA_NORMAL) if channelId == d.channelId => stay()

    // we only care about this event in NORMAL and SHUTDOWN state, and there may be cases where the task is not cancelled
    case Event(_: RevocationTimeout, _) => stay()

    // we reschedule with a random delay to prevent herd effect when there are a lot of channels
    case Event(c: CurrentBlockHeight, _) =>
      context.system.scheduler.scheduleOnce(blockProcessingDelay, self, ProcessCurrentBlockHeight(c))
      stay()

    // we only care about this event in NORMAL and SHUTDOWN state, and we never unregister to the event stream
    case Event(ProcessCurrentBlockHeight(_), _) => stay()

    // we only care about this event in NORMAL and SHUTDOWN state, and we never unregister to the event stream
    case Event(CurrentFeerates(_), _) => stay()

    // we only care about this event in NORMAL state
    case Event(_: BroadcastChannelUpdate, _) => stay()

    // we receive this when we tell the peer to disconnect
    case Event("disconnecting", _) => stay()

    // funding tx was confirmed in time, let's just ignore this
    case Event(BITCOIN_FUNDING_TIMEOUT, d) if d.channelData().nonEmpty => stay()

    // peer doesn't cancel the timer
    case Event(TickChannelOpenTimeout, _) => stay()

    case Event(WatchFundingSpentTriggered(tx), d) if d.channelData().exists(_.commitments.localCommit.commitTxAndRemoteSig.commitTx.tx.txid == tx.txid) =>
      log.warning(s"processing local commit spent in catch-all handler")
      spendLocalCurrent(d.channelData().get)
  }

  onTransition {
    case WAIT_FOR_INIT_INTERNAL -> WAIT_FOR_INIT_INTERNAL => () // called at channel initialization
    case state -> nextState =>
      if (state != nextState) {
        val commitments_opt = nextStateData.channelData().map(_.commitments)
        context.system.eventStream.publish(ChannelStateChanged(self, nextStateData.channelId, peer, remoteNodeId, state, nextState, commitments_opt))
      }

      if (nextState == CLOSED) {
        // channel is closed, scheduling this actor for self destruction
        context.system.scheduler.scheduleOnce(10 seconds, self, Symbol("shutdown"))
      }
      if (nextState == OFFLINE) {
        // we can cancel the timer, we are not expecting anything when disconnected
        cancelTimer(RevocationTimeout.toString)
      }

      // if channel is private, we send the channel_update directly to remote
      // they need it "to learn the other end's forwarding parameters" (BOLT 7)
      (state, nextState, stateData, nextStateData) match {
        case (_, _, DATA_NORMAL(d1), DATA_NORMAL(d2)) if !d1.commitments.announceChannel && !d1.buried && d2.buried =>
          // for a private channel, when the tx was just buried we need to send the channel_update to our peer (even if it didn't change)
          send(d2.channelUpdate)
        case (SYNCING, NORMAL, DATA_SYNCING(d1), DATA_NORMAL(d2)) if !d1.commitments.announceChannel && d2.buried =>
          // otherwise if we're coming back online, we rebroadcast the latest channel_update
          // this makes sure that if the channel_update was missed, we have a chance to re-send it
          send(d2.channelUpdate)
        case (_, _, DATA_NORMAL(d1), DATA_NORMAL(d2)) if !d1.commitments.announceChannel && d1.channelUpdate != d2.channelUpdate && d2.buried =>
          // otherwise, we only send it when it is different, and tx is already buried
          send(d2.channelUpdate)
        case _ => ()
      }

      val channelUpdate_opt = (state, nextState, stateData, nextStateData) match {
        // ORDER MATTERS!
        case (WAIT_FOR_INIT_INTERNAL, OFFLINE, _, DATA_OFFLINE(d: ChannelData.Normal)) => Some(d)
        case (OFFLINE, OFFLINE, DATA_OFFLINE(d1: ChannelData.Normal), DATA_OFFLINE(d2: ChannelData.Normal)) if d1.channelUpdate == d2.channelUpdate && d1.channelAnnouncement == d2.channelAnnouncement => None
        case (OFFLINE, SYNCING, DATA_OFFLINE(d1: ChannelData.Normal), DATA_SYNCING(d2: ChannelData.Normal)) if d1.channelUpdate == d2.channelUpdate && d1.channelAnnouncement == d2.channelAnnouncement => None
        case (SYNCING, NORMAL, DATA_SYNCING(d1: ChannelData.Normal), DATA_NORMAL(d2)) if d1.channelUpdate == d2.channelUpdate && d1.channelAnnouncement == d2.channelAnnouncement => None
        case (NORMAL, NORMAL, DATA_NORMAL(d1), DATA_NORMAL(d2)) if d1.channelUpdate == d2.channelUpdate && d1.channelAnnouncement == d2.channelAnnouncement => None
        case (NORMAL, OFFLINE, DATA_NORMAL(d1), DATA_OFFLINE(d2: ChannelData.Normal)) if d1.channelUpdate == d2.channelUpdate && d1.channelAnnouncement == d2.channelAnnouncement => None
        case (WAIT_FOR_FUNDING_LOCKED | NORMAL | SYNCING, NORMAL, _, DATA_NORMAL(d)) => Some(d)
        case (NORMAL | OFFLINE, OFFLINE, _, DATA_OFFLINE(d: ChannelData.Normal)) => Some(d)
        case _ => None
      }
      channelUpdate_opt.foreach(d => {
        log.info("emitting channel_update={} enabled={} ", d.channelUpdate, d.channelUpdate.channelFlags.isEnabled)
        context.system.eventStream.publish(LocalChannelUpdate(self, d.channelId, d.shortChannelId, d.commitments.remoteParams.nodeId, d.channelAnnouncement, d.channelUpdate, d.commitments))
      })

      // When a channel that could previously be used to relay payments starts closing, we advertise the fact that this channel can't be used for payments anymore
      // If the channel is private we don't really need to tell the counterparty because it is already aware that the channel is being closed
      (state, nextState, stateData, nextStateData) match {
        case (NORMAL, SHUTDOWN | NEGOTIATING | CLOSING | CLOSED | ERR_INFORMATION_LEAK | WAIT_FOR_REMOTE_PUBLISH_FUTURE_COMMITMENT, DATA_NORMAL(d), _) => context.system.eventStream.publish(LocalChannelDown(self, d.channelId, d.shortChannelId, d.commitments.remoteParams.nodeId))
        case (SYNCING, SHUTDOWN | NEGOTIATING | CLOSING | CLOSED | ERR_INFORMATION_LEAK | WAIT_FOR_REMOTE_PUBLISH_FUTURE_COMMITMENT, DATA_SYNCING(d: ChannelData.Normal), _) => context.system.eventStream.publish(LocalChannelDown(self, d.channelId, d.shortChannelId, d.commitments.remoteParams.nodeId))
        case (OFFLINE, SHUTDOWN | NEGOTIATING | CLOSING | CLOSED | ERR_INFORMATION_LEAK | WAIT_FOR_REMOTE_PUBLISH_FUTURE_COMMITMENT, DATA_OFFLINE(d: ChannelData.Normal), _) => context.system.eventStream.publish(LocalChannelDown(self, d.channelId, d.shortChannelId, d.commitments.remoteParams.nodeId))
        case _ => ()
      }

      // When we change our channel update parameters (e.g. relay fees), we want to advertize it.
      (stateData, nextStateData) match {
        case (DATA_NORMAL(d1), DATA_OFFLINE(d2: ChannelData.Normal)) => maybeEmitChannelUpdateChangedEvent(newUpdate = d2.channelUpdate, oldUpdate_opt = Some(d1.channelUpdate), d2)
        case (DATA_SYNCING(d1: ChannelData.Normal), DATA_NORMAL(d2)) => maybeEmitChannelUpdateChangedEvent(newUpdate = d2.channelUpdate, oldUpdate_opt = Some(d1.channelUpdate), d2)
        case (DATA_NORMAL(d1), DATA_NORMAL(d2)) => maybeEmitChannelUpdateChangedEvent(newUpdate = d2.channelUpdate, oldUpdate_opt = Some(d1.channelUpdate), d2)
        case (_: DATA_WAIT_FOR_FUNDING_LOCKED, DATA_NORMAL(d2)) => maybeEmitChannelUpdateChangedEvent(newUpdate = d2.channelUpdate, oldUpdate_opt = None, d2)
        case _ => ()
      }
  }

  /** Metrics */
  onTransition {
    case state -> nextState if state != nextState =>
      if (state != WAIT_FOR_INIT_INTERNAL) Metrics.ChannelsCount.withTag(Tags.State, state.toString).decrement()
      if (nextState != WAIT_FOR_INIT_INTERNAL) Metrics.ChannelsCount.withTag(Tags.State, nextState.toString).increment()
  }

  /** Check pending settlement commands */
  onTransition {
    case _ -> CLOSING =>
      PendingCommandsDb.getSettlementCommands(nodeParams.db.pendingCommands, nextStateData.channelId) match {
        case Nil =>
          log.debug("nothing to replay")
        case cmds =>
          log.info("replaying {} unacked fulfills/fails", cmds.size)
          cmds.foreach(self ! _) // they all have commit = false
      }
    case SYNCING -> (NORMAL | SHUTDOWN) =>
      PendingCommandsDb.getSettlementCommands(nodeParams.db.pendingCommands, nextStateData.channelId) match {
        case Nil =>
          log.debug("nothing to replay")
        case cmds =>
          log.info("replaying {} unacked fulfills/fails", cmds.size)
          cmds.foreach(self ! _) // they all have commit = false
          self ! CMD_SIGN() // so we can sign all of them at once
      }
  }

  /** Fail outgoing unsigned htlcs right away when transitioning from NORMAL to CLOSING */
  onTransition {
    case NORMAL -> CLOSING =>
      (nextStateData: @unchecked) match {
        case DATA_CLOSING(d) =>
          d.commitments.localChanges.proposed.collect {
            case add: UpdateAddHtlc => relayer ! RES_ADD_SETTLED(d.commitments.originChannels(add.id), add, HtlcResult.ChannelFailureBeforeSigned)
          }
      }
  }

  /*
          888    888        d8888 888b    888 8888888b.  888      8888888888 8888888b.   .d8888b.
          888    888       d88888 8888b   888 888  "Y88b 888      888        888   Y88b d88P  Y88b
          888    888      d88P888 88888b  888 888    888 888      888        888    888 Y88b.
          8888888888     d88P 888 888Y88b 888 888    888 888      8888888    888   d88P  "Y888b.
          888    888    d88P  888 888 Y88b888 888    888 888      888        8888888P"      "Y88b.
          888    888   d88P   888 888  Y88888 888    888 888      888        888 T88b         "888
          888    888  d8888888888 888   Y8888 888  .d88P 888      888        888  T88b  Y88b  d88P
          888    888 d88P     888 888    Y888 8888888P"  88888888 8888888888 888   T88b  "Y8888P"
   */

  private def handleCurrentFeerate(c: CurrentFeerates, d: ChannelData) = {
    val networkFeeratePerKw = nodeParams.onChainFeeConf.getCommitmentFeerate(remoteNodeId, d.commitments.channelType, d.commitments.capacity, Some(c))
    val currentFeeratePerKw = d.commitments.localCommit.spec.commitTxFeerate
    val shouldUpdateFee = d.commitments.localParams.isFunder && nodeParams.onChainFeeConf.shouldUpdateFee(currentFeeratePerKw, networkFeeratePerKw)
    val shouldClose = !d.commitments.localParams.isFunder &&
      nodeParams.onChainFeeConf.feerateToleranceFor(d.commitments.remoteNodeId).isFeeDiffTooHigh(d.commitments.channelType, networkFeeratePerKw, currentFeeratePerKw) &&
      d.commitments.hasPendingOrProposedHtlcs // we close only if we have HTLCs potentially at risk
    if (shouldUpdateFee) {
      self ! CMD_UPDATE_FEE(networkFeeratePerKw, commit = true)
      stay()
    } else if (shouldClose) {
      handleLocalError(FeerateTooDifferent(d.channelId, localFeeratePerKw = networkFeeratePerKw, remoteFeeratePerKw = d.commitments.localCommit.spec.commitTxFeerate), Some(c))
    } else {
      stay()
    }
  }

  /**
   * This is used to check for the commitment fees when the channel is not operational but we have something at stake
   *
   * @param c the new feerates
   * @param d the channel commtiments
   * @return
   */
  private def handleCurrentFeerateDisconnected(c: CurrentFeerates, d: ChannelData) = {
    val networkFeeratePerKw = nodeParams.onChainFeeConf.getCommitmentFeerate(remoteNodeId, d.commitments.channelType, d.commitments.capacity, Some(c))
    val currentFeeratePerKw = d.commitments.localCommit.spec.commitTxFeerate
    // if the network fees are too high we risk to not be able to confirm our current commitment
    val shouldClose = networkFeeratePerKw > currentFeeratePerKw &&
      nodeParams.onChainFeeConf.feerateToleranceFor(d.commitments.remoteNodeId).isFeeDiffTooHigh(d.commitments.channelType, networkFeeratePerKw, currentFeeratePerKw) &&
      d.commitments.hasPendingOrProposedHtlcs // we close only if we have HTLCs potentially at risk
    if (shouldClose) {
      if (nodeParams.onChainFeeConf.closeOnOfflineMismatch) {
        log.warning(s"closing OFFLINE channel due to fee mismatch: currentFeeratePerKw=$currentFeeratePerKw networkFeeratePerKw=$networkFeeratePerKw")
        handleLocalError(FeerateTooDifferent(d.channelId, localFeeratePerKw = currentFeeratePerKw, remoteFeeratePerKw = networkFeeratePerKw), Some(c))
      } else {
        log.warning(s"channel is OFFLINE but its fee mismatch is over the threshold: currentFeeratePerKw=$currentFeeratePerKw networkFeeratePerKw=$networkFeeratePerKw")
        stay()
      }
    } else {
      stay()
    }
  }

  private def handleCommandSuccess(c: channel.Command, newData: ChannelStateData) = {
    val replyTo_opt = c match {
      case hasOptionalReplyTo: HasOptionalReplyToCommand => hasOptionalReplyTo.replyTo_opt
      case hasReplyTo: HasReplyToCommand => if (hasReplyTo.replyTo == ActorRef.noSender) Some(sender()) else Some(hasReplyTo.replyTo)
    }
    replyTo_opt.foreach { replyTo =>
      replyTo ! RES_SUCCESS(c, newData.channelId)
    }
    stay() using newData
  }

  private def handleAddHtlcCommandError(c: CMD_ADD_HTLC, cause: ChannelException, channelUpdate: Option[ChannelUpdate]) = {
    log.warning(s"${cause.getMessage} while processing cmd=${c.getClass.getSimpleName} in state=$stateName")
    val replyTo = if (c.replyTo == ActorRef.noSender) sender() else c.replyTo
    replyTo ! RES_ADD_FAILED(c, cause, channelUpdate)
    context.system.eventStream.publish(ChannelErrorOccurred(self, stateData.channelId, remoteNodeId, LocalError(cause), isFatal = false))
    stay()
  }

  private def handleCommandError(cause: ChannelException, c: channel.Command) = {
    log.warning(s"${cause.getMessage} while processing cmd=${c.getClass.getSimpleName} in state=$stateName")
    val replyTo_opt = c match {
      case hasOptionalReplyTo: HasOptionalReplyToCommand => hasOptionalReplyTo.replyTo_opt
      case hasReplyTo: HasReplyToCommand => if (hasReplyTo.replyTo == ActorRef.noSender) Some(sender()) else Some(hasReplyTo.replyTo)
    }
    replyTo_opt.foreach(replyTo => replyTo ! RES_FAILURE(c, cause))
    context.system.eventStream.publish(ChannelErrorOccurred(self, stateData.channelId, remoteNodeId, LocalError(cause), isFatal = false))
    stay()
  }

  private def watchFundingTx(commitments: Commitments, additionalKnownSpendingTxs: Set[ByteVector32] = Set.empty): Unit = {
    // TODO: should we wait for an acknowledgment from the watcher?
    val knownSpendingTxs = Set(commitments.localCommit.commitTxAndRemoteSig.commitTx.tx.txid, commitments.remoteCommit.txid) ++ commitments.remoteNextCommitInfo.left.toSeq.map(_.nextRemoteCommit.txid).toSet ++ additionalKnownSpendingTxs
    blockchain ! WatchFundingSpent(self, commitments.commitInput.outPoint.txid, commitments.commitInput.outPoint.index.toInt, knownSpendingTxs)
    // TODO: implement this? (not needed if we use a reasonable min_depth)
    //blockchain ! WatchLost(self, commitments.commitInput.outPoint.txid, nodeParams.channelConf.minDepthBlocks, BITCOIN_FUNDING_LOST)
  }

  /**
   * When we are funder, we use this function to detect when our funding tx has been double-spent (by another transaction
   * that we made for some reason). If the funding tx has been double spent we can forget about the channel.
   */
  private def checkDoubleSpent(fundingTx: Transaction): Unit = {
    log.debug(s"checking status of funding tx txid=${fundingTx.txid}")
    wallet.doubleSpent(fundingTx).onComplete {
      case Success(true) =>
        log.warning(s"funding tx has been double spent! fundingTxid=${fundingTx.txid} fundingTx=$fundingTx")
        self ! BITCOIN_FUNDING_PUBLISH_FAILED
      case Success(false) => ()
      case Failure(t) => log.error(t, s"error while testing status of funding tx fundingTxid=${fundingTx.txid}: ")
    }
  }

  private def handleGetFundingTx(getTxResponse: GetTxWithMetaResponse, waitingSince: BlockHeight, fundingTx_opt: Option[Transaction]) = {
    import getTxResponse._
    tx_opt match {
      case Some(_) => () // the funding tx exists, nothing to do
      case None =>
        fundingTx_opt match {
          case Some(fundingTx) =>
            // if we are funder, we never give up
            // we cannot correctly set the fee, but it was correctly set when we initially published the transaction
            log.info(s"republishing the funding tx...")
            txPublisher ! PublishFinalTx(fundingTx, fundingTx.txIn.head.outPoint, "funding", 0 sat, None)
            // we also check if the funding tx has been double-spent
            checkDoubleSpent(fundingTx)
            context.system.scheduler.scheduleOnce(1 day, blockchain.toClassic, GetTxWithMeta(self, txid))
          case None if (nodeParams.currentBlockHeight - waitingSince) > FUNDING_TIMEOUT_FUNDEE =>
            // if we are fundee, we give up after some time
            log.warning(s"funding tx hasn't been published in ${nodeParams.currentBlockHeight - waitingSince} blocks")
            self ! BITCOIN_FUNDING_TIMEOUT
          case None =>
            // let's wait a little longer
            log.info(s"funding tx still hasn't been published in ${nodeParams.currentBlockHeight - waitingSince} blocks, will wait ${FUNDING_TIMEOUT_FUNDEE - (nodeParams.currentBlockHeight - waitingSince)} more blocks...")
            context.system.scheduler.scheduleOnce(1 day, blockchain.toClassic, GetTxWithMeta(self, txid))
        }
    }
    stay()
  }

  private def handleFundingPublishFailed(d: ChannelData) = {
    log.error(s"failed to publish funding tx")
    val exc = ChannelFundingError(d.channelId)
    val error = Error(d.channelId, exc.getMessage)
    // NB: we don't use the handleLocalError handler because it would result in the commit tx being published, which we don't want:
    // implementation *guarantees* that in case of BITCOIN_FUNDING_PUBLISH_FAILED, the funding tx hasn't and will never be published, so we can close the channel right away
    context.system.eventStream.publish(ChannelErrorOccurred(self, d.channelId, remoteNodeId, LocalError(exc), isFatal = true))
    goto(CLOSED) using DATA_CLOSED(Some(d)) sending error
  }

  private def handleFundingTimeout(d: ChannelData) = {
    log.warning(s"funding tx hasn't been confirmed in time, cancelling channel delay=$FUNDING_TIMEOUT_FUNDEE")
    val exc = FundingTxTimedout(d.channelId)
    val error = Error(d.channelId, exc.getMessage)
    context.system.eventStream.publish(ChannelErrorOccurred(self, d.channelId, remoteNodeId, LocalError(exc), isFatal = true))
    goto(CLOSED) using DATA_CLOSED(Some(d)) sending error
  }

  private def handleRevocationTimeout(revocationTimeout: RevocationTimeout, d: ChannelData) = {
    d.commitments.remoteNextCommitInfo match {
      case Left(waitingForRevocation) if revocationTimeout.remoteCommitNumber + 1 == waitingForRevocation.nextRemoteCommit.index =>
        log.warning(s"waited for too long for a revocation to remoteCommitNumber=${revocationTimeout.remoteCommitNumber}, disconnecting")
        revocationTimeout.peer ! Peer.Disconnect(remoteNodeId)
      case _ => ()
    }
    stay()
  }

  private def handleAddDisconnected(c: CMD_ADD_HTLC, d: ChannelData.Normal) = {
    log.info(s"rejecting htlc request in state=$stateName")
    // in order to reduce gossip spam, we don't disable the channel right away when disconnected
    // we will only emit a new channel_update with the disable flag set if someone tries to use that channel
    if (d.channelUpdate.channelFlags.isEnabled) {
      // if the channel isn't disabled we generate a new channel_update
      log.info("updating channel_update announcement (reason=disabled)")
      val channelUpdate1 = Announcements.makeChannelUpdate(nodeParams.chainHash, nodeParams.privateKey, remoteNodeId, d.shortChannelId, d.channelUpdate.cltvExpiryDelta, d.channelUpdate.htlcMinimumMsat, d.channelUpdate.feeBaseMsat, d.channelUpdate.feeProportionalMillionths, d.commitments.capacity.toMilliSatoshi, enable = false)
      // then we update the state and replay the request
      self forward c
      // we use goto() to fire transitions
      goto(OFFLINE) using DATA_OFFLINE(d.copy(channelUpdate = channelUpdate1))
    } else {
      // channel is already disabled, we reply to the request
      val error = ChannelUnavailable(d.channelId)
      handleAddHtlcCommandError(c, error, Some(d.channelUpdate)) // can happen if we are in OFFLINE or SYNCING state (channelUpdate will have enable=false)
    }
  }

  private def handleUpdateRelayFeeDisconnected(c: CMD_UPDATE_RELAY_FEE, d: ChannelData.Normal) = {
    val channelUpdate1 = Announcements.makeChannelUpdate(nodeParams.chainHash, nodeParams.privateKey, remoteNodeId, d.shortChannelId, c.cltvExpiryDelta_opt.getOrElse(d.channelUpdate.cltvExpiryDelta), d.channelUpdate.htlcMinimumMsat, c.feeBase, c.feeProportionalMillionths, d.commitments.capacity.toMilliSatoshi, enable = false)
    log.info(s"updating relay fees: prev={} next={}", d.channelUpdate.toStringShort, channelUpdate1.toStringShort)
    val replyTo = if (c.replyTo == ActorRef.noSender) sender() else c.replyTo
    replyTo ! RES_SUCCESS(c, d.channelId)
    // We're in OFFLINE state, by using stay() instead of goto() we skip the transition handler and won't broadcast the
    // new update right away. The goal is to not emit superfluous updates when the channel is unusable. At reconnection
    // there will be a state transition SYNCING->NORMAL which will cause the update to be broadcast.
    // However, we still need to advertise that the channel_update parameters have changed, so we manually call the method
    maybeEmitChannelUpdateChangedEvent(newUpdate = channelUpdate1, oldUpdate_opt = Some(d.channelUpdate), d)
    stay() using DATA_OFFLINE(d.copy(channelUpdate = channelUpdate1)) storing()
  }

  private def handleSyncFailure(channelReestablish: ChannelReestablish, syncFailure: SyncResult.Failure, d: ChannelData) = {
    syncFailure match {
      case res: SyncResult.LocalLateProven =>
        log.error(s"counterparty proved that we have an outdated (revoked) local commitment!!! ourLocalCommitmentNumber=${res.ourLocalCommitmentNumber} theirRemoteCommitmentNumber=${res.theirRemoteCommitmentNumber}")
        // their data checks out, we indeed seem to be using an old revoked commitment, and must absolutely *NOT* publish it, because that would be a cheating attempt and they
        // would punish us by taking all the funds in the channel
        handleOutdatedCommitment(channelReestablish, d)
      case res: Syncing.SyncResult.LocalLateUnproven =>
        log.error(s"our local commitment is in sync, but counterparty says that they have a more recent remote commitment than the one we know of (they could be lying)!!! ourRemoteCommitmentNumber=${res.ourRemoteCommitmentNumber} theirCommitmentNumber=${res.theirLocalCommitmentNumber}")
        // there is no way to make sure that they are saying the truth, the best thing to do is "call their bluff" and
        // ask them to publish their commitment right now. If they weren't lying and they do publish their commitment,
        // we need to remember their commitment point in order to be able to claim our outputs
        handleOutdatedCommitment(channelReestablish, d)
      case res: Syncing.SyncResult.RemoteLying =>
        log.error(s"counterparty is lying about us having an outdated commitment!!! ourLocalCommitmentNumber=${res.ourLocalCommitmentNumber} theirRemoteCommitmentNumber=${res.theirRemoteCommitmentNumber}")
        // they are deliberately trying to fool us into thinking we have a late commitment
        handleLocalError(InvalidRevokedCommitProof(d.channelId, res.ourLocalCommitmentNumber, res.theirRemoteCommitmentNumber, res.invalidPerCommitmentSecret), Some(channelReestablish))
      case SyncResult.RemoteLate =>
        log.error("counterparty appears to be using an outdated commitment, they may request a force-close, standing by...")
        stay()
    }
  }

  private def maybeEmitChannelUpdateChangedEvent(newUpdate: ChannelUpdate, oldUpdate_opt: Option[ChannelUpdate], d: ChannelData.Normal): Unit = {
    if (oldUpdate_opt.isEmpty || !Announcements.areSameIgnoreFlags(newUpdate, oldUpdate_opt.get)) {
      context.system.eventStream.publish(ChannelUpdateParametersChanged(self, d.channelId, newUpdate.shortChannelId, d.commitments.remoteNodeId, newUpdate))
    }
  }

  private def handleNewBlock(c: CurrentBlockHeight, d: ChannelData) = {
    val timedOutOutgoing = d.commitments.timedOutOutgoingHtlcs(c.blockHeight)
    val almostTimedOutIncoming = d.commitments.almostTimedOutIncomingHtlcs(c.blockHeight, nodeParams.channelConf.fulfillSafetyBeforeTimeout)
    if (timedOutOutgoing.nonEmpty) {
      // Downstream timed out.
      handleLocalError(HtlcsTimedoutDownstream(d.channelId, timedOutOutgoing), Some(c))
    } else if (almostTimedOutIncoming.nonEmpty) {
      // Upstream is close to timing out, we need to test if we have funds at risk: htlcs for which we know the preimage
      // that are still in our commitment (upstream will try to timeout on-chain).
      val relayedFulfills = d.commitments.localChanges.all.collect { case u: UpdateFulfillHtlc => u.id }.toSet
      val offendingRelayedHtlcs = almostTimedOutIncoming.filter(htlc => relayedFulfills.contains(htlc.id))
      if (offendingRelayedHtlcs.nonEmpty) {
        handleLocalError(HtlcsWillTimeoutUpstream(d.channelId, offendingRelayedHtlcs), Some(c))
      } else {
        // There might be pending fulfill commands that we haven't relayed yet.
        // Since this involves a DB call, we only want to check it if all the previous checks failed (this is the slow path).
        val pendingRelayFulfills = nodeParams.db.pendingCommands.listSettlementCommands(d.channelId).collect { case c: CMD_FULFILL_HTLC => c.id }
        val offendingPendingRelayFulfills = almostTimedOutIncoming.filter(htlc => pendingRelayFulfills.contains(htlc.id))
        if (offendingPendingRelayFulfills.nonEmpty) {
          handleLocalError(HtlcsWillTimeoutUpstream(d.channelId, offendingPendingRelayFulfills), Some(c))
        } else {
          stay()
        }
      }
    } else {
      stay()
    }
  }

  /**
   * Return full information about a known closing tx.
   */
  private def getMutualClosePublished(tx: Transaction, closingTxProposed: List[List[ClosingTxProposed]]): ClosingTx = {
    // they can publish a closing tx with any sig we sent them, even if we are not done negotiating
    val proposedTx_opt = closingTxProposed.flatten.find(_.unsignedTx.tx.txid == tx.txid)
    require(proposedTx_opt.nonEmpty, s"closing tx not found in our proposed transactions: tx=$tx")
    // they added their signature, so we use their version of the transaction
    proposedTx_opt.get.unsignedTx.copy(tx = tx)
  }

  private def doPublish(closingTx: ClosingTx, isFunder: Boolean): Unit = {
    // the funder pays the fee
    val fee = if (isFunder) closingTx.fee else 0.sat
    txPublisher ! PublishFinalTx(closingTx, fee, None)
    blockchain ! WatchTxConfirmed(self, closingTx.tx.txid, nodeParams.channelConf.minDepthBlocks)
  }

  /**
   * This helper method will publish txs only if they haven't yet reached minDepth
   */
  private def publishIfNeeded(txs: Iterable[PublishTx], irrevocablySpent: Map[OutPoint, Transaction]): Unit = {
    val (skip, process) = txs.partition(publishTx => Closing.inputAlreadySpent(publishTx.input, irrevocablySpent))
    process.foreach { publishTx => txPublisher ! publishTx }
    skip.foreach(publishTx => log.info("no need to republish tx spending {}:{}, it has already been confirmed", publishTx.input.txid, publishTx.input.index))
  }

  /**
   * This helper method will watch txs only if they haven't yet reached minDepth
   */
  private def watchConfirmedIfNeeded(txs: Iterable[Transaction], irrevocablySpent: Map[OutPoint, Transaction]): Unit = {
    val (skip, process) = txs.partition(Closing.inputsAlreadySpent(_, irrevocablySpent))
    process.foreach(tx => blockchain ! WatchTxConfirmed(self, tx.txid, nodeParams.channelConf.minDepthBlocks))
    skip.foreach(tx => log.info(s"no need to watch txid=${tx.txid}, it has already been confirmed"))
  }

  /**
   * This helper method will watch txs only if the utxo they spend hasn't already been irrevocably spent
   *
   * @param parentTx transaction which outputs will be watched
   * @param outputs  outputs that will be watched. They must be a subset of the outputs of the `parentTx`
   */
  private def watchSpentIfNeeded(parentTx: Transaction, outputs: Iterable[OutPoint], irrevocablySpent: Map[OutPoint, Transaction]): Unit = {
    outputs.foreach { output =>
      require(output.txid == parentTx.txid && output.index < parentTx.txOut.size, s"output doesn't belong to the given parentTx: output=${output.txid}:${output.index} (expected txid=${parentTx.txid} index < ${parentTx.txOut.size})")
    }
    val (skip, process) = outputs.partition(irrevocablySpent.contains)
    process.foreach(output => blockchain ! WatchOutputSpent(self, parentTx.txid, output.index.toInt, Set.empty))
    skip.foreach(output => log.info(s"no need to watch output=${output.txid}:${output.index}, it has already been spent by txid=${irrevocablySpent.get(output).map(_.txid)}"))
  }

  private def handleRemoteSpentCurrent(commitTx: Transaction, d: ChannelData) = {
    log.warning(s"they published their current commit in txid=${commitTx.txid}")
    require(commitTx.txid == d.commitments.remoteCommit.txid, "txid mismatch")

    context.system.eventStream.publish(TransactionPublished(d.channelId, remoteNodeId, commitTx, Closing.commitTxFee(d.commitments.commitInput, commitTx, d.commitments.localParams.isFunder), "remote-commit"))
    val remoteCommitPublished = Helpers.Closing.claimRemoteCommitTxOutputs(keyManager, d.commitments, d.commitments.remoteCommit, commitTx, nodeParams.currentBlockHeight, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets)
    val nextData = d match {
      case closing: ChannelData.Closing => closing.copy(remoteCommitPublished = Some(remoteCommitPublished))
      case negotiating: ChannelData.Negotiating => ChannelData.Closing(d.commitments, fundingTx = None, waitingSince = nodeParams.currentBlockHeight, negotiating.closingTxProposed.flatten.map(_.unsignedTx), remoteCommitPublished = Some(remoteCommitPublished))
      case waitForFundingConfirmed: ChannelData.WaitingForFundingConfirmed => ChannelData.Closing(d.commitments, fundingTx = waitForFundingConfirmed.fundingTx, waitingSince = nodeParams.currentBlockHeight, mutualCloseProposed = Nil, remoteCommitPublished = Some(remoteCommitPublished))
      case _ => ChannelData.Closing(d.commitments, fundingTx = None, waitingSince = nodeParams.currentBlockHeight, mutualCloseProposed = Nil, remoteCommitPublished = Some(remoteCommitPublished))
    }
    goto(CLOSING) using DATA_CLOSING(nextData) storing() calling doPublish(remoteCommitPublished, d.commitments)
  }

  private def handleRemoteSpentFuture(commitTx: Transaction, d: ChannelData.WaitingForRemotePublishFutureCommitment) = {
    log.warning(s"they published their future commit (because we asked them to) in txid=${commitTx.txid}")
    context.system.eventStream.publish(TransactionPublished(d.channelId, remoteNodeId, commitTx, Closing.commitTxFee(d.commitments.commitInput, commitTx, d.commitments.localParams.isFunder), "future-remote-commit"))
    d.commitments.channelFeatures match {
      case ct if ct.paysDirectlyToWallet =>
        val remoteCommitPublished = RemoteCommitPublished(commitTx, None, Map.empty, List.empty, Map.empty)
        val nextData = ChannelData.Closing(d.commitments, fundingTx = None, waitingSince = nodeParams.currentBlockHeight, Nil, futureRemoteCommitPublished = Some(remoteCommitPublished))
        goto(CLOSING) using DATA_CLOSING(nextData) storing() // we don't need to claim our main output in the remote commit because it already spends to our wallet address
      case _ =>
        val remotePerCommitmentPoint = d.remoteChannelReestablish.myCurrentPerCommitmentPoint
        val remoteCommitPublished = Helpers.Closing.claimRemoteCommitMainOutput(keyManager, d.commitments, remotePerCommitmentPoint, commitTx, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets)
        val nextData = ChannelData.Closing(d.commitments, fundingTx = None, waitingSince = nodeParams.currentBlockHeight, Nil, futureRemoteCommitPublished = Some(remoteCommitPublished))
        goto(CLOSING) using DATA_CLOSING(nextData) storing() calling doPublish(remoteCommitPublished, d.commitments)
    }
  }

  private def handleRemoteSpentNext(commitTx: Transaction, d: ChannelData) = {
    log.warning(s"they published their next commit in txid=${commitTx.txid}")
    require(d.commitments.remoteNextCommitInfo.isLeft, "next remote commit must be defined")
    val Left(waitingForRevocation) = d.commitments.remoteNextCommitInfo
    val remoteCommit = waitingForRevocation.nextRemoteCommit
    require(commitTx.txid == remoteCommit.txid, "txid mismatch")

    context.system.eventStream.publish(TransactionPublished(d.channelId, remoteNodeId, commitTx, Closing.commitTxFee(d.commitments.commitInput, commitTx, d.commitments.localParams.isFunder), "next-remote-commit"))
    val remoteCommitPublished = Helpers.Closing.claimRemoteCommitTxOutputs(keyManager, d.commitments, remoteCommit, commitTx, nodeParams.currentBlockHeight, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets)
    val nextData = d match {
      case closing: ChannelData.Closing => closing.copy(nextRemoteCommitPublished = Some(remoteCommitPublished))
      case negotiating: ChannelData.Negotiating => ChannelData.Closing(d.commitments, fundingTx = None, waitingSince = nodeParams.currentBlockHeight, negotiating.closingTxProposed.flatten.map(_.unsignedTx), nextRemoteCommitPublished = Some(remoteCommitPublished))
      // NB: if there is a next commitment, we can't be in DATA_WAIT_FOR_FUNDING_CONFIRMED so we don't have the case where fundingTx is defined
      case _ => ChannelData.Closing(d.commitments, fundingTx = None, waitingSince = nodeParams.currentBlockHeight, mutualCloseProposed = Nil, nextRemoteCommitPublished = Some(remoteCommitPublished))
    }
    goto(CLOSING) using DATA_CLOSING(nextData) storing() calling doPublish(remoteCommitPublished, d.commitments)
  }

  private def doPublish(remoteCommitPublished: RemoteCommitPublished, commitments: Commitments): Unit = {
    import remoteCommitPublished._

    val redeemableHtlcTxs = claimHtlcTxs.values.flatten.map(tx => PublishReplaceableTx(tx, commitments))
    val publishQueue = claimMainOutputTx.map(tx => PublishFinalTx(tx, tx.fee, None)).toSeq ++ redeemableHtlcTxs
    publishIfNeeded(publishQueue, irrevocablySpent)

    // we watch:
    // - the commitment tx itself, so that we can handle the case where we don't have any outputs
    // - 'final txs' that send funds to our wallet and that spend outputs that only us control
    val watchConfirmedQueue = List(commitTx) ++ claimMainOutputTx.map(_.tx)
    watchConfirmedIfNeeded(watchConfirmedQueue, irrevocablySpent)

    // we watch outputs of the commitment tx that both parties may spend
    val watchSpentQueue = claimHtlcTxs.keys
    watchSpentIfNeeded(commitTx, watchSpentQueue, irrevocablySpent)
  }

  private def handleRemoteSpentOther(tx: Transaction, d: ChannelData) = {
    log.warning(s"funding tx spent in txid=${tx.txid}")
    Helpers.Closing.claimRevokedRemoteCommitTxOutputs(keyManager, d.commitments, tx, nodeParams.db.channels, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets) match {
      case Some(revokedCommitPublished) =>
        log.warning(s"txid=${tx.txid} was a revoked commitment, publishing the penalty tx")
        context.system.eventStream.publish(TransactionPublished(d.channelId, remoteNodeId, tx, Closing.commitTxFee(d.commitments.commitInput, tx, d.commitments.localParams.isFunder), "revoked-commit"))
        val exc = FundingTxSpent(d.channelId, tx)
        val error = Error(d.channelId, exc.getMessage)

        val nextData = d match {
          case closing: ChannelData.Closing => closing.copy(revokedCommitPublished = closing.revokedCommitPublished :+ revokedCommitPublished)
          case negotiating: ChannelData.Negotiating => ChannelData.Closing(d.commitments, fundingTx = None, waitingSince = nodeParams.currentBlockHeight, negotiating.closingTxProposed.flatten.map(_.unsignedTx), revokedCommitPublished = revokedCommitPublished :: Nil)
          // NB: if there is a revoked commitment, we can't be in DATA_WAIT_FOR_FUNDING_CONFIRMED so we don't have the case where fundingTx is defined
          case _ => ChannelData.Closing(d.commitments, fundingTx = None, waitingSince = nodeParams.currentBlockHeight, mutualCloseProposed = Nil, revokedCommitPublished = revokedCommitPublished :: Nil)
        }
        goto(CLOSING) using DATA_CLOSING(nextData) storing() calling doPublish(revokedCommitPublished) sending error
      case None =>
        // the published tx was neither their current commitment nor a revoked one
        log.error(s"couldn't identify txid=${tx.txid}, something very bad is going on!!!")
        context.system.eventStream.publish(NotifyNodeOperator(NotificationsLogger.Error, s"funding tx ${d.commitments.commitInput.outPoint.txid} of channel ${d.channelId} was spent by an unknown transaction, indicating that your DB has lost data or your node has been breached: please contact the dev team."))
        goto(ERR_INFORMATION_LEAK) using DATA_ERR_INFORMATION_LEAK(d)
    }
  }

  private def doPublish(revokedCommitPublished: RevokedCommitPublished): Unit = {
    import revokedCommitPublished._

    val publishQueue = (claimMainOutputTx ++ mainPenaltyTx ++ htlcPenaltyTxs ++ claimHtlcDelayedPenaltyTxs).map(tx => PublishFinalTx(tx, tx.fee, None))
    publishIfNeeded(publishQueue, irrevocablySpent)

    // we watch:
    // - the commitment tx itself, so that we can handle the case where we don't have any outputs
    // - 'final txs' that send funds to our wallet and that spend outputs that only us control
    val watchConfirmedQueue = List(commitTx) ++ claimMainOutputTx.map(_.tx)
    watchConfirmedIfNeeded(watchConfirmedQueue, irrevocablySpent)

    // we watch outputs of the commitment tx that both parties may spend
    val watchSpentQueue = (mainPenaltyTx ++ htlcPenaltyTxs).map(_.input.outPoint)
    watchSpentIfNeeded(commitTx, watchSpentQueue, irrevocablySpent)
  }

  private def handleInformationLeak(tx: Transaction, d: ChannelData) = {
    // this is never supposed to happen !!
    log.error(s"our funding tx ${d.commitments.commitInput.outPoint.txid} was spent by txid=${tx.txid}!!")
    context.system.eventStream.publish(NotifyNodeOperator(NotificationsLogger.Error, s"funding tx ${d.commitments.commitInput.outPoint.txid} of channel ${d.channelId} was spent by an unknown transaction, indicating that your DB has lost data or your node has been breached: please contact the dev team."))
    val exc = FundingTxSpent(d.channelId, tx)
    val error = Error(d.channelId, exc.getMessage)

    // let's try to spend our current local tx
    val commitTx = d.commitments.fullySignedLocalCommitTx(keyManager).tx
    val localCommitPublished = Helpers.Closing.claimCurrentLocalCommitTxOutputs(keyManager, d.commitments, commitTx, nodeParams.currentBlockHeight, nodeParams.onChainFeeConf.feeEstimator, nodeParams.onChainFeeConf.feeTargets)

    goto(ERR_INFORMATION_LEAK) using DATA_ERR_INFORMATION_LEAK(d) calling doPublish(localCommitPublished, d.commitments) sending error
  }

  private def handleOutdatedCommitment(channelReestablish: ChannelReestablish, d: ChannelData) = {
    val exc = PleasePublishYourCommitment(d.channelId)
    val error = Error(d.channelId, exc.getMessage)
    goto(WAIT_FOR_REMOTE_PUBLISH_FUTURE_COMMITMENT) using DATA_WAIT_FOR_REMOTE_PUBLISH_FUTURE_COMMITMENT(ChannelData.WaitingForRemotePublishFutureCommitment(d.commitments, channelReestablish)) storing() sending error
  }

  override def mdc(currentMessage: Any): MDC = {
    val category_opt = LogCategory(currentMessage)
    val id = currentMessage match {
      case INPUT_RESTORED(data) => data.channelId
      case _ => stateData.channelId
    }
    Logs.mdc(category_opt, remoteNodeId_opt = Some(remoteNodeId), channelId_opt = Some(id))
  }

  // we let the peer decide what to do
  override val supervisorStrategy: OneForOneStrategy = OneForOneStrategy(loggingEnabled = true) { case _ => SupervisorStrategy.Escalate }

  override def aroundReceive(receive: Actor.Receive, msg: Any): Unit = {
    KamonExt.time(ProcessMessage.withTag("MessageType", msg.getClass.getSimpleName)) {
      super.aroundReceive(receive, msg)
    }
  }

  initialize()

}
