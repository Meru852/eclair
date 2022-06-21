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

package fr.acinq.eclair.blockchain.bitcoind

import akka.actor.Status.Failure
import akka.pattern.pipe
import akka.testkit.TestProbe
import fr.acinq.bitcoin
import fr.acinq.bitcoin.ScriptFlags
import fr.acinq.bitcoin.SigHash.SIGHASH_ALL
import fr.acinq.bitcoin.SigVersion.SIGVERSION_WITNESS_V0
import fr.acinq.bitcoin.scalacompat.Crypto.{PrivateKey, PublicKey, der2compact}
import fr.acinq.bitcoin.scalacompat.{Block, BtcDouble, ByteVector32, Crypto, MilliBtcDouble, OutPoint, Satoshi, SatoshiLong, Script, ScriptWitness, Transaction, TxIn, TxOut}
import fr.acinq.eclair.blockchain.OnChainWallet.{MakeFundingTxResponse, OnChainBalance}
import fr.acinq.eclair.blockchain.WatcherSpec.{createSpendManyP2WPKH, createSpendP2WPKH}
import fr.acinq.eclair.blockchain.bitcoind.BitcoindService.BitcoinReq
import fr.acinq.eclair.blockchain.bitcoind.rpc.BitcoinCoreClient._
import fr.acinq.eclair.blockchain.bitcoind.rpc.BitcoinJsonRPCAuthMethod.UserPassword
import fr.acinq.eclair.blockchain.bitcoind.rpc.{BasicBitcoinJsonRPCClient, BitcoinCoreClient, JsonRPCError}
import fr.acinq.eclair.blockchain.fee.FeeratePerKw
import fr.acinq.eclair.transactions.Transactions.{InputInfo, fee2rate, weight2fee}
import fr.acinq.eclair.transactions.{Scripts, Transactions}
import fr.acinq.eclair.{BlockHeight, TestConstants, TestKitBaseClass, addressToPublicKeyScript, randomKey}
import grizzled.slf4j.Logging
import org.json4s.JsonAST._
import org.json4s.{DefaultFormats, Formats}
import org.scalatest.BeforeAndAfterAll
import org.scalatest.funsuite.AnyFunSuiteLike
import scodec.bits.ByteVector

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.DurationInt
import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Random, Try}

class BitcoinCoreClientSpec extends TestKitBaseClass with BitcoindService with AnyFunSuiteLike with BeforeAndAfterAll with Logging {

  implicit val formats: Formats = DefaultFormats

  override def beforeAll(): Unit = {
    startBitcoind()
    waitForBitcoindReady()
  }

  override def afterAll(): Unit = {
    stopBitcoind()
  }

  test("encrypt wallet") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)
    val walletPassword = Random.alphanumeric.take(8).mkString
    sender.send(bitcoincli, BitcoinReq("encryptwallet", walletPassword))
    sender.expectMsgType[JString](60 seconds)
    restartBitcoind(sender)

    val pubkeyScript = Script.write(Script.pay2wsh(Scripts.multiSig2of2(randomKey().publicKey, randomKey().publicKey)))
    bitcoinClient.makeFundingTx(pubkeyScript, 50 millibtc, FeeratePerKw(10000 sat)).pipeTo(sender.ref)
    val error = sender.expectMsgType[Failure].cause.asInstanceOf[JsonRPCError].error
    assert(error.message.contains("Please enter the wallet passphrase with walletpassphrase first"))

    sender.send(bitcoincli, BitcoinReq("walletpassphrase", walletPassword, 3600)) // wallet stay unlocked for 3600s
    sender.expectMsgType[JValue]
  }

  test("fund transactions") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    val txToRemote = {
      val txNotFunded = Transaction(2, Nil, TxOut(150000 sat, Script.pay2wpkh(randomKey().publicKey)) :: Nil, 0)
      bitcoinClient.fundTransaction(txNotFunded, FundTransactionOptions(TestConstants.feeratePerKw)).pipeTo(sender.ref)
      val fundTxResponse = sender.expectMsgType[FundTransactionResponse]
      assert(fundTxResponse.changePosition.nonEmpty)
      assert(fundTxResponse.amountIn > 0.sat)
      assert(fundTxResponse.fee > 0.sat)
      fundTxResponse.tx.txIn.foreach(txIn => assert(txIn.signatureScript.isEmpty && txIn.witness.isNull))
      fundTxResponse.tx.txIn.foreach(txIn => assert(txIn.sequence == bitcoin.TxIn.SEQUENCE_FINAL - 2))

      bitcoinClient.signTransaction(fundTxResponse.tx, Nil).pipeTo(sender.ref)
      val signTxResponse = sender.expectMsgType[SignTransactionResponse]
      assert(signTxResponse.complete)
      assert(signTxResponse.tx.txOut.size == 2)

      bitcoinClient.publishTransaction(signTxResponse.tx).pipeTo(sender.ref)
      sender.expectMsg(signTxResponse.tx.txid)
      generateBlocks(1)
      signTxResponse.tx
    }
    {
      // txs with no outputs are not supported.
      val emptyTx = Transaction(2, Nil, Nil, 0)
      bitcoinClient.fundTransaction(emptyTx, FundTransactionOptions(TestConstants.feeratePerKw)).pipeTo(sender.ref)
      sender.expectMsgType[Failure]
    }
    {
      // bitcoind requires that "all existing inputs must have their previous output transaction be in the wallet".
      val txNonWalletInputs = Transaction(2, Seq(TxIn(OutPoint(txToRemote, 0), Nil, 0), TxIn(OutPoint(txToRemote, 1), Nil, 0)), Seq(TxOut(100000 sat, Script.pay2wpkh(randomKey().publicKey))), 0)
      bitcoinClient.fundTransaction(txNonWalletInputs, FundTransactionOptions(TestConstants.feeratePerKw)).pipeTo(sender.ref)
      sender.expectMsgType[Failure]
    }
    {
      // we can increase the feerate.
      bitcoinClient.fundTransaction(Transaction(2, Nil, TxOut(250000 sat, Script.pay2wpkh(randomKey().publicKey)) :: Nil, 0), FundTransactionOptions(TestConstants.feeratePerKw)).pipeTo(sender.ref)
      val fundTxResponse1 = sender.expectMsgType[FundTransactionResponse]
      bitcoinClient.fundTransaction(fundTxResponse1.tx, FundTransactionOptions(TestConstants.feeratePerKw * 2)).pipeTo(sender.ref)
      val fundTxResponse2 = sender.expectMsgType[FundTransactionResponse]
      assert(fundTxResponse1.tx !== fundTxResponse2.tx)
      assert(fundTxResponse1.fee < fundTxResponse2.fee)
    }
    {
      // we can control where the change output is inserted and opt-out of RBF.
      val txManyOutputs = Transaction(2, Nil, TxOut(410000 sat, Script.pay2wpkh(randomKey().publicKey)) :: TxOut(230000 sat, Script.pay2wpkh(randomKey().publicKey)) :: Nil, 0)
      bitcoinClient.fundTransaction(txManyOutputs, FundTransactionOptions(TestConstants.feeratePerKw, replaceable = false, changePosition = Some(1))).pipeTo(sender.ref)
      val fundTxResponse = sender.expectMsgType[FundTransactionResponse]
      assert(fundTxResponse.tx.txOut.size == 3)
      assert(fundTxResponse.changePosition == Some(1))
      assert(!Set(230000 sat, 410000 sat).contains(fundTxResponse.tx.txOut(1).amount))
      assert(Set(230000 sat, 410000 sat) == Set(fundTxResponse.tx.txOut.head.amount, fundTxResponse.tx.txOut.last.amount))
      fundTxResponse.tx.txIn.foreach(txIn => assert(txIn.sequence == bitcoin.TxIn.SEQUENCE_FINAL - 1))
    }
  }

  test("absence of rounding") {
    val txIn = Transaction(1, Nil, Nil, 42)
    val hexOut = "02000000013361e994f6bd5cbe9dc9e8cb3acdc12bc1510a3596469d9fc03cfddd71b223720000000000feffffff02c821354a00000000160014b6aa25d6f2a692517f2cf1ad55f243a5ba672cac404b4c0000000000220020822eb4234126c5fc84910e51a161a9b7af94eb67a2344f7031db247e0ecc2f9200000000"

    0 to 9 foreach { satoshi =>
      val apiAmount = JDecimal(BigDecimal(s"0.0000000$satoshi"))
      val rpcClient = new BasicBitcoinJsonRPCClient(rpcAuthMethod = UserPassword("foo", "bar"), host = "localhost", port = 0) {
        override def invoke(method: String, params: Any*)(implicit ec: ExecutionContext): Future[JValue] = method match {
          case "getbalances" => Future(JObject("mine" -> JObject("trusted" -> apiAmount, "untrusted_pending" -> apiAmount)))(ec)
          case "getmempoolinfo" => Future(JObject("mempoolminfee" -> JDecimal(0.0002)))(ec)
          case "fundrawtransaction" => Future(JObject(List("hex" -> JString(hexOut), "changepos" -> JInt(1), "fee" -> apiAmount)))(ec)
          case _ => Future.failed(new RuntimeException(s"Test BasicBitcoinJsonRPCClient: method $method is not supported"))
        }
      }

      val sender = TestProbe()
      val bitcoinClient = new BitcoinCoreClient(rpcClient)
      bitcoinClient.onChainBalance().pipeTo(sender.ref)
      assert(sender.expectMsgType[OnChainBalance] == OnChainBalance(Satoshi(satoshi), Satoshi(satoshi)))

      bitcoinClient.fundTransaction(txIn, FundTransactionOptions(FeeratePerKw(250 sat))).pipeTo(sender.ref)
      val fundTxResponse = sender.expectMsgType[FundTransactionResponse]
      assert(fundTxResponse.fee == Satoshi(satoshi))
    }
  }

  test("create/commit/rollback funding txs") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    bitcoinClient.onChainBalance().pipeTo(sender.ref)
    assert(sender.expectMsgType[OnChainBalance].confirmed > 0.sat)

    bitcoinClient.getReceiveAddress().pipeTo(sender.ref)
    val address = sender.expectMsgType[String]
    assert(Try(addressToPublicKeyScript(address, Block.RegtestGenesisBlock.hash)).isSuccess)

    val fundingTxs = for (_ <- 0 to 3) yield {
      val pubkeyScript = Script.write(Script.pay2wsh(Scripts.multiSig2of2(randomKey().publicKey, randomKey().publicKey)))
      bitcoinClient.makeFundingTx(pubkeyScript, Satoshi(500), FeeratePerKw(250 sat)).pipeTo(sender.ref)
      val fundingTx = sender.expectMsgType[MakeFundingTxResponse].fundingTx
      bitcoinClient.publishTransaction(fundingTx.copy(txIn = Nil)).pipeTo(sender.ref) // try publishing an invalid version of the tx
      sender.expectMsgType[Failure]
      bitcoinClient.rollback(fundingTx).pipeTo(sender.ref) // rollback the locked outputs
      assert(sender.expectMsgType[Boolean])

      // now fund a tx with correct feerate
      bitcoinClient.makeFundingTx(pubkeyScript, 50 millibtc, FeeratePerKw(250 sat)).pipeTo(sender.ref)
      sender.expectMsgType[MakeFundingTxResponse].fundingTx
    }

    assert(getLocks(sender).size == 4)

    bitcoinClient.commit(fundingTxs(0)).pipeTo(sender.ref)
    assert(sender.expectMsgType[Boolean])

    bitcoinClient.rollback(fundingTxs(1)).pipeTo(sender.ref)
    assert(sender.expectMsgType[Boolean])

    bitcoinClient.commit(fundingTxs(2)).pipeTo(sender.ref)
    assert(sender.expectMsgType[Boolean])

    bitcoinClient.rollback(fundingTxs(3)).pipeTo(sender.ref)
    assert(sender.expectMsgType[Boolean])

    bitcoinClient.getTransaction(fundingTxs(0).txid).pipeTo(sender.ref)
    sender.expectMsg(fundingTxs(0))

    bitcoinClient.getTransaction(fundingTxs(2).txid).pipeTo(sender.ref)
    sender.expectMsg(fundingTxs(2))

    // NB: from 0.17.0 on bitcoin core will clear locks when a tx is published
    assert(getLocks(sender).isEmpty)
  }

  test("ensure feerate is always above min-relay-fee") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    val pubkeyScript = Script.write(Script.pay2wsh(Scripts.multiSig2of2(randomKey().publicKey, randomKey().publicKey)))
    // 200 sat/kw is below the min-relay-fee
    bitcoinClient.makeFundingTx(pubkeyScript, 5 millibtc, FeeratePerKw(200 sat)).pipeTo(sender.ref)
    val MakeFundingTxResponse(fundingTx, _, _) = sender.expectMsgType[MakeFundingTxResponse]

    bitcoinClient.commit(fundingTx).pipeTo(sender.ref)
    sender.expectMsg(true)
  }

  test("unlock failed funding txs") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    bitcoinClient.onChainBalance().pipeTo(sender.ref)
    assert(sender.expectMsgType[OnChainBalance].confirmed > 0.sat)

    bitcoinClient.getReceiveAddress().pipeTo(sender.ref)
    val address = sender.expectMsgType[String]
    assert(Try(addressToPublicKeyScript(address, Block.RegtestGenesisBlock.hash)).isSuccess)

    assert(getLocks(sender).isEmpty)

    val pubkeyScript = Script.write(Script.pay2wsh(Scripts.multiSig2of2(randomKey().publicKey, randomKey().publicKey)))
    bitcoinClient.makeFundingTx(pubkeyScript, 50 millibtc, FeeratePerKw(10000 sat)).pipeTo(sender.ref)
    val MakeFundingTxResponse(fundingTx, _, _) = sender.expectMsgType[MakeFundingTxResponse]

    bitcoinClient.commit(fundingTx).pipeTo(sender.ref)
    sender.expectMsg(true)

    bitcoinClient.onChainBalance().pipeTo(sender.ref)
    assert(sender.expectMsgType[OnChainBalance].confirmed > 0.sat)
  }

  test("unlock utxos when transaction is published") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)
    generateBlocks(1) // generate a block to ensure we start with an empty mempool

    // create a first transaction with multiple inputs
    val tx1 = {
      val fundedTxs = (1 to 3).map(_ => {
        val txNotFunded = Transaction(2, Nil, TxOut(15000 sat, Script.pay2wpkh(randomKey().publicKey)) :: Nil, 0)
        bitcoinClient.fundTransaction(txNotFunded, FundTransactionOptions(TestConstants.feeratePerKw, lockUtxos = true)).pipeTo(sender.ref)
        sender.expectMsgType[FundTransactionResponse].tx
      })
      val fundedTx = Transaction(2, fundedTxs.flatMap(_.txIn), fundedTxs.flatMap(_.txOut), 0)
      assert(fundedTx.txIn.length >= 3)

      // tx inputs should be locked
      val lockedUtxos = getLocks(sender)
      fundedTx.txIn.foreach(txIn => assert(lockedUtxos.contains(txIn.outPoint)))

      bitcoinClient.signTransaction(fundedTx, Nil).pipeTo(sender.ref)
      val signTxResponse = sender.expectMsgType[SignTransactionResponse]
      bitcoinClient.publishTransaction(signTxResponse.tx).pipeTo(sender.ref)
      sender.expectMsg(signTxResponse.tx.txid)
      // once the tx is published, the inputs should be automatically unlocked
      assert(getLocks(sender).isEmpty)
      signTxResponse.tx
    }

    // create a second transaction that double-spends one of the inputs of the first transaction
    val tx2 = {
      val txNotFunded = tx1.copy(txIn = tx1.txIn.take(1))
      bitcoinClient.fundTransaction(txNotFunded, FundTransactionOptions(TestConstants.feeratePerKw * 2, lockUtxos = true)).pipeTo(sender.ref)
      val fundedTx = sender.expectMsgType[FundTransactionResponse].tx
      assert(fundedTx.txIn.length >= 2) // we added at least one new input

      // newly added inputs should be locked
      val lockedUtxos = getLocks(sender)
      fundedTx.txIn.foreach(txIn => assert(lockedUtxos.contains(txIn.outPoint)))

      bitcoinClient.signTransaction(fundedTx, Nil).pipeTo(sender.ref)
      val signTxResponse = sender.expectMsgType[SignTransactionResponse]
      bitcoinClient.publishTransaction(signTxResponse.tx).pipeTo(sender.ref)
      sender.expectMsg(signTxResponse.tx.txid)
      // once the tx is published, the inputs should be automatically unlocked
      assert(getLocks(sender).isEmpty)
      signTxResponse.tx
    }

    // tx2 replaced tx1 in the mempool
    bitcoinClient.getMempool().pipeTo(sender.ref)
    val mempoolTxs = sender.expectMsgType[Seq[Transaction]]
    assert(mempoolTxs.length == 1)
    assert(mempoolTxs.head.txid == tx2.txid)
    assert(tx2.txIn.map(_.outPoint).intersect(tx1.txIn.map(_.outPoint)).length == 1)
  }

  test("unlock transaction inputs if publishing fails") {
    val sender = TestProbe()
    val pubkeyScript = Script.write(Script.pay2wsh(Scripts.multiSig2of2(randomKey().publicKey, randomKey().publicKey)))
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    // create a huge tx so we make sure it has > 1 inputs
    bitcoinClient.makeFundingTx(pubkeyScript, 250 btc, FeeratePerKw(1000 sat)).pipeTo(sender.ref)
    val MakeFundingTxResponse(fundingTx, outputIndex, _) = sender.expectMsgType[MakeFundingTxResponse]

    // spend the first 2 inputs
    val tx1 = fundingTx.copy(
      txIn = fundingTx.txIn.take(2),
      txOut = fundingTx.txOut.updated(outputIndex, fundingTx.txOut(outputIndex).copy(amount = 50 btc))
    )
    bitcoinClient.signTransaction(tx1).pipeTo(sender.ref)
    val SignTransactionResponse(tx2, true) = sender.expectMsgType[SignTransactionResponse]

    bitcoinClient.commit(tx2).pipeTo(sender.ref)
    assert(sender.expectMsgType[Boolean])

    // fundingTx inputs are still locked except for the first 2 that were just spent
    val expectedLocks = fundingTx.txIn.drop(2).map(_.outPoint).toSet
    awaitCond({
      val locks = getLocks(sender)
      expectedLocks -- locks isEmpty
    }, max = 10 seconds, interval = 1 second)

    // publishing fundingTx will fail as its first 2 inputs are already spent by tx above in the mempool
    bitcoinClient.commit(fundingTx).pipeTo(sender.ref)
    val result = sender.expectMsgType[Boolean]
    assert(!result)

    // and all locked inputs should now be unlocked
    awaitCond({
      val locks = getLocks(sender)
      locks isEmpty
    }, max = 10 seconds, interval = 1 second)
  }

  test("unlock outpoints correctly") {
    val sender = TestProbe()
    val pubkeyScript = Script.write(Script.pay2wsh(Scripts.multiSig2of2(randomKey().publicKey, randomKey().publicKey)))
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    {
      // test #1: unlock outpoints that are actually locked
      // create a huge tx so we make sure it has > 1 inputs
      bitcoinClient.makeFundingTx(pubkeyScript, 250 btc, FeeratePerKw(1000 sat)).pipeTo(sender.ref)
      val MakeFundingTxResponse(fundingTx, _, _) = sender.expectMsgType[MakeFundingTxResponse]
      assert(fundingTx.txIn.size > 2)
      assert(getLocks(sender) == fundingTx.txIn.map(_.outPoint).toSet)
      bitcoinClient.rollback(fundingTx).pipeTo(sender.ref)
      assert(sender.expectMsgType[Boolean])
    }
    {
      // test #2: some outpoints are locked, some are unlocked
      bitcoinClient.makeFundingTx(pubkeyScript, 250 btc, FeeratePerKw(1000 sat)).pipeTo(sender.ref)
      val MakeFundingTxResponse(fundingTx, _, _) = sender.expectMsgType[MakeFundingTxResponse]
      assert(fundingTx.txIn.size > 2)
      assert(getLocks(sender) == fundingTx.txIn.map(_.outPoint).toSet)

      // unlock the first 2 outpoints
      val tx1 = fundingTx.copy(txIn = fundingTx.txIn.take(2))
      bitcoinClient.rollback(tx1).pipeTo(sender.ref)
      assert(sender.expectMsgType[Boolean])
      assert(getLocks(sender) == fundingTx.txIn.drop(2).map(_.outPoint).toSet)

      // and try to unlock all outpoints: it should work too
      bitcoinClient.rollback(fundingTx).pipeTo(sender.ref)
      assert(sender.expectMsgType[Boolean])
      assert(getLocks(sender) isEmpty)
    }
  }

  test("sign transactions") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    val nonWalletKey = randomKey()
    val opts = FundTransactionOptions(TestConstants.feeratePerKw, changePosition = Some(1))
    bitcoinClient.fundTransaction(Transaction(2, Nil, Seq(TxOut(250000 sat, Script.pay2wpkh(nonWalletKey.publicKey))), 0), opts).pipeTo(sender.ref)
    val fundedTx = sender.expectMsgType[FundTransactionResponse].tx
    bitcoinClient.signTransaction(fundedTx, Nil).pipeTo(sender.ref)
    val txToRemote = sender.expectMsgType[SignTransactionResponse].tx
    bitcoinClient.publishTransaction(txToRemote).pipeTo(sender.ref)
    sender.expectMsg(txToRemote.txid)
    generateBlocks(1)

    {
      bitcoinClient.fundTransaction(Transaction(2, Nil, Seq(TxOut(400000 sat, Script.pay2wpkh(randomKey().publicKey))), 0), opts).pipeTo(sender.ref)
      val fundTxResponse = sender.expectMsgType[FundTransactionResponse]
      val txWithNonWalletInput = fundTxResponse.tx.copy(txIn = TxIn(OutPoint(txToRemote, 0), ByteVector.empty, 0) +: fundTxResponse.tx.txIn)
      val walletInputTxs = txWithNonWalletInput.txIn.tail.map(txIn => {
        bitcoinClient.getTransaction(txIn.outPoint.txid).pipeTo(sender.ref)
        sender.expectMsgType[Transaction]
      })

      // bitcoind returns an error if there are unsigned non-wallet input.
      bitcoinClient.signTransaction(txWithNonWalletInput, Nil).pipeTo(sender.ref)
      val Failure(JsonRPCError(error)) = sender.expectMsgType[Failure]
      assert(error.message.contains(txToRemote.txid.toHex))

      // we can ignore that error with allowIncomplete = true, and in that case bitcoind signs the wallet inputs.
      bitcoinClient.signTransaction(txWithNonWalletInput, Nil, allowIncomplete = true).pipeTo(sender.ref)
      val signTxResponse1 = sender.expectMsgType[SignTransactionResponse]
      assert(!signTxResponse1.complete)
      signTxResponse1.tx.txIn.tail.foreach(walletTxIn => assert(walletTxIn.witness.stack.nonEmpty))

      // if the non-wallet inputs are signed, bitcoind signs the remaining wallet inputs.
      val nonWalletSig = Transaction.signInput(txWithNonWalletInput, 0, Script.pay2pkh(nonWalletKey.publicKey), bitcoin.SigHash.SIGHASH_ALL, txToRemote.txOut.head.amount, bitcoin.SigVersion.SIGVERSION_WITNESS_V0, nonWalletKey)
      val nonWalletWitness = ScriptWitness(Seq(nonWalletSig, nonWalletKey.publicKey.value))
      val txWithSignedNonWalletInput = txWithNonWalletInput.updateWitness(0, nonWalletWitness)
      bitcoinClient.signTransaction(txWithSignedNonWalletInput, Nil).pipeTo(sender.ref)
      val signTxResponse2 = sender.expectMsgType[SignTransactionResponse]
      assert(signTxResponse2.complete)
      Transaction.correctlySpends(signTxResponse2.tx, txToRemote +: walletInputTxs, bitcoin.ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }
    {
      // bitcoind does not sign inputs that have already been confirmed.
      bitcoinClient.signTransaction(fundedTx, Nil).pipeTo(sender.ref)
      val Failure(JsonRPCError(error)) = sender.expectMsgType[Failure]
      assert(error.message.contains("not found or already spent"))
    }
    {
      // bitcoind lets us double-spend ourselves.
      bitcoinClient.fundTransaction(Transaction(2, Nil, Seq(TxOut(75000 sat, Script.pay2wpkh(randomKey().publicKey))), 0), opts).pipeTo(sender.ref)
      val fundTxResponse = sender.expectMsgType[FundTransactionResponse]
      bitcoinClient.signTransaction(fundTxResponse.tx, Nil).pipeTo(sender.ref)
      assert(sender.expectMsgType[SignTransactionResponse].complete)
      bitcoinClient.signTransaction(fundTxResponse.tx.copy(txOut = Seq(TxOut(85000 sat, Script.pay2wpkh(randomKey().publicKey)))), Nil).pipeTo(sender.ref)
      assert(sender.expectMsgType[SignTransactionResponse].complete)
    }
    {
      // create an unconfirmed utxo to a non-wallet address.
      bitcoinClient.fundTransaction(Transaction(2, Nil, Seq(TxOut(125000 sat, Script.pay2wpkh(nonWalletKey.publicKey))), 0), opts).pipeTo(sender.ref)
      bitcoinClient.signTransaction(sender.expectMsgType[FundTransactionResponse].tx, Nil).pipeTo(sender.ref)
      val unconfirmedTx = sender.expectMsgType[SignTransactionResponse].tx
      bitcoinClient.publishTransaction(unconfirmedTx).pipeTo(sender.ref)
      sender.expectMsg(unconfirmedTx.txid)
      // bitcoind lets us use this unconfirmed non-wallet input.
      bitcoinClient.fundTransaction(Transaction(2, Nil, Seq(TxOut(350000 sat, Script.pay2wpkh(randomKey().publicKey))), 0), opts).pipeTo(sender.ref)
      val fundTxResponse = sender.expectMsgType[FundTransactionResponse]
      val txWithUnconfirmedInput = fundTxResponse.tx.copy(txIn = TxIn(OutPoint(unconfirmedTx, 0), ByteVector.empty, 0) +: fundTxResponse.tx.txIn)
      val nonWalletSig = Transaction.signInput(txWithUnconfirmedInput, 0, Script.pay2pkh(nonWalletKey.publicKey), bitcoin.SigHash.SIGHASH_ALL, unconfirmedTx.txOut.head.amount, bitcoin.SigVersion.SIGVERSION_WITNESS_V0, nonWalletKey)
      val nonWalletWitness = ScriptWitness(Seq(nonWalletSig, nonWalletKey.publicKey.value))
      val txWithSignedUnconfirmedInput = txWithUnconfirmedInput.updateWitness(0, nonWalletWitness)
      val previousTx = PreviousTx(Transactions.InputInfo(OutPoint(unconfirmedTx.txid, 0), unconfirmedTx.txOut.head, Script.pay2pkh(nonWalletKey.publicKey)), nonWalletWitness)
      bitcoinClient.signTransaction(txWithSignedUnconfirmedInput, Seq(previousTx)).pipeTo(sender.ref)
      assert(sender.expectMsgType[SignTransactionResponse].complete)
    }
  }

  test("publish transaction idempotent") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    val priv = randomKey()
    val noInputTx = Transaction(2, Nil, TxOut(6.btc.toSatoshi, Script.pay2wpkh(priv.publicKey)) :: Nil, 0)
    bitcoinClient.fundTransaction(noInputTx, FundTransactionOptions(TestConstants.feeratePerKw)).pipeTo(sender.ref)
    val fundTxResponse = sender.expectMsgType[FundTransactionResponse]
    val changePos = fundTxResponse.changePosition.get
    bitcoinClient.signTransaction(fundTxResponse.tx, Nil).pipeTo(sender.ref)
    val tx = sender.expectMsgType[SignTransactionResponse].tx

    // we publish the tx a first time
    bitcoinClient.publishTransaction(tx).pipeTo(sender.ref)
    sender.expectMsg(tx.txid)
    // we publish the tx a second time to test idempotence
    bitcoinClient.publishTransaction(tx).pipeTo(sender.ref)
    sender.expectMsg(tx.txid)
    // let's confirm the tx
    generateBlocks(1)
    // and publish the tx a third time to test idempotence
    bitcoinClient.publishTransaction(tx).pipeTo(sender.ref)
    sender.expectMsg(tx.txid)

    // now let's spend the output of the tx
    val spendingTx = {
      val address = getNewAddress(sender)
      val pos = if (changePos == 0) 1 else 0
      bitcoinrpcclient.invoke("createrawtransaction", Array(Map("txid" -> tx.txid.toHex, "vout" -> pos)), Map(address -> 5.999)).pipeTo(sender.ref)
      val JString(unsignedTxStr) = sender.expectMsgType[JValue]
      val unsignedTx = Transaction.read(unsignedTxStr)
      val sig = Transaction.signInput(unsignedTx, 0, Script.pay2pkh(priv.publicKey), bitcoin.SigHash.SIGHASH_ALL, 6.btc.toSatoshi, bitcoin.SigVersion.SIGVERSION_WITNESS_V0, priv)
      unsignedTx.updateWitness(0, Script.witnessPay2wpkh(priv.publicKey, sig))
    }
    bitcoinClient.publishTransaction(spendingTx).pipeTo(sender.ref)
    sender.expectMsg(spendingTx.txid)

    // and publish the tx a fourth time to test idempotence
    bitcoinClient.publishTransaction(tx).pipeTo(sender.ref)
    sender.expectMsg(tx.txid)
    // let's confirm the tx
    generateBlocks(1)
    // and publish the tx a fifth time to test idempotence
    bitcoinClient.publishTransaction(tx).pipeTo(sender.ref)
    sender.expectMsg(tx.txid)
  }

  test("publish invalid transactions") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    // that tx has inputs that don't exist
    val txWithUnknownInputs = Transaction.read("02000000000101b9e2a3f518fd74e696d258fed3c78c43f84504e76c99212e01cf225083619acf00000000000d0199800136b34b00000000001600145464ce1e5967773922506e285780339d72423244040047304402206795df1fd93c285d9028c384aacf28b43679f1c3f40215fd7bd1abbfb816ee5a022047a25b8c128e692d4717b6dd7b805aa24ecbbd20cfd664ab37a5096577d4a15d014730440220770f44121ed0e71ec4b482dded976f2febd7500dfd084108e07f3ce1e85ec7f5022025b32dc0d551c47136ce41bfb80f5a10de95c0babb22a3ae2d38e6688b32fcb20147522102c2662ab3e4fa18a141d3be3317c6ee134aff10e6cd0a91282a25bf75c0481ebc2102e952dd98d79aa796289fa438e4fdeb06ed8589ff2a0f032b0cfcb4d7b564bc3252aea58d1120")
    bitcoinClient.publishTransaction(txWithUnknownInputs).pipeTo(sender.ref)
    sender.expectMsgType[Failure]

    // invalid txs shouldn't be found in either the mempool or the blockchain
    bitcoinClient.getTxConfirmations(txWithUnknownInputs.txid).pipeTo(sender.ref)
    sender.expectMsg(None)

    bitcoinClient.fundTransaction(Transaction(2, Nil, TxOut(100000 sat, Script.pay2wpkh(randomKey().publicKey)) :: Nil, 0), FundTransactionOptions(TestConstants.feeratePerKw)).pipeTo(sender.ref)
    val txUnsignedInputs = sender.expectMsgType[FundTransactionResponse].tx
    bitcoinClient.publishTransaction(txUnsignedInputs).pipeTo(sender.ref)
    sender.expectMsgType[Failure]

    bitcoinClient.signTransaction(txUnsignedInputs, Nil).pipeTo(sender.ref)
    val signTxResponse = sender.expectMsgType[SignTransactionResponse]
    assert(signTxResponse.complete)

    val txWithNoOutputs = signTxResponse.tx.copy(txOut = Nil)
    bitcoinClient.publishTransaction(txWithNoOutputs).pipeTo(sender.ref)
    sender.expectMsgType[Failure]

    bitcoinClient.getBlockHeight().pipeTo(sender.ref)
    val blockHeight = sender.expectMsgType[BlockHeight]
    val txWithFutureCltv = signTxResponse.tx.copy(lockTime = blockHeight.toLong + 1)
    bitcoinClient.publishTransaction(txWithFutureCltv).pipeTo(sender.ref)
    sender.expectMsgType[Failure]

    bitcoinClient.publishTransaction(signTxResponse.tx).pipeTo(sender.ref)
    sender.expectMsg(signTxResponse.tx.txid)
  }

  test("publish package of transactions") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    val fundingPrivKey = randomKey()
    val balancePubKey = randomKey().publicKey
    val anchorAmount = 330.sat
    val commitTx = {
      val noInputCommitTx = Transaction(2, Nil, TxOut(1.btc.toSatoshi, Script.pay2wpkh(balancePubKey)) :: TxOut(anchorAmount, Script.pay2wsh(Scripts.anchor(fundingPrivKey.publicKey))) :: Nil, 0)
      bitcoinClient.fundTransaction(noInputCommitTx, FundTransactionOptions(TestConstants.feeratePerKw)).pipeTo(sender.ref)
      val fundTxResponse = sender.expectMsgType[FundTransactionResponse]
      val balanceAmount = fundTxResponse.amountIn - anchorAmount
      val zeroFeeCommitTx = fundTxResponse.tx.copy(txOut = TxOut(balanceAmount, Script.pay2wpkh(balancePubKey)) :: TxOut(anchorAmount, Script.pay2wsh(Scripts.anchor(fundingPrivKey.publicKey))) :: Nil)
      bitcoinClient.signTransaction(zeroFeeCommitTx, Nil).pipeTo(sender.ref)
      sender.expectMsgType[SignTransactionResponse].tx
    }

    // We can't publish the commit tx alone.
    bitcoinClient.publishTransaction(commitTx).pipeTo(sender.ref)
    sender.expectMsgType[Failure]

    val (anchorCpfp, fees) = {
      val notFundedTx = Transaction(2, Nil, TxOut(1000 sat, Script.pay2wpkh(randomKey().publicKey)) :: Nil, 0)
      bitcoinClient.fundTransaction(notFundedTx, FundTransactionOptions(TestConstants.feeratePerKw)).pipeTo(sender.ref)
      val fundTxResponse = sender.expectMsgType[FundTransactionResponse]
      val unsignedTx = fundTxResponse.tx.copy(txIn = TxIn(OutPoint(commitTx, 1), Nil, 0) +: fundTxResponse.tx.txIn)
      val redeemScript = Script.write(Scripts.anchor(fundingPrivKey.publicKey))
      val sig = Transaction.signInput(unsignedTx, inputIndex = 0, redeemScript, SIGHASH_ALL, anchorAmount, SIGVERSION_WITNESS_V0, fundingPrivKey)
      val anchorWitness = Scripts.witnessAnchor(Crypto.der2compact(sig), redeemScript)
      val partiallySignedTx = unsignedTx.updateWitness(0, anchorWitness)
      val previousTx = PreviousTx(InputInfo(OutPoint(commitTx, 1), commitTx.txOut(1), redeemScript), anchorWitness)
      bitcoinClient.signTransaction(partiallySignedTx, Seq(previousTx)).pipeTo(sender.ref)
      (sender.expectMsgType[SignTransactionResponse].tx, fundTxResponse.fee)
    }

    val packageFeerate = fee2rate(fees, anchorCpfp.weight() + commitTx.weight())
    println(s"estimated package-feerate=$packageFeerate")

    // But we can publish a package.
    bitcoinClient.publishPackage(Seq(commitTx, anchorCpfp)).pipeTo(sender.ref)
    val txids = sender.expectMsgType[Seq[ByteVector32]]
    assert(txids.toSet === Set(commitTx.txid, anchorCpfp.txid))

    {
      bitcoinClient.getMempool().pipeTo(sender.ref)
      val mempoolTxs = sender.expectMsgType[Seq[Transaction]]
      assert(mempoolTxs.length === 2)
      assert(mempoolTxs.contains(commitTx))
    }

    // And it's idempotent.
    bitcoinClient.publishPackage(Seq(commitTx, anchorCpfp)).pipeTo(sender.ref)
    assert(sender.expectMsgType[Seq[ByteVector32]].toSet == Set(commitTx.txid, anchorCpfp.txid))

    // We can then fee-bump the child.
    val anchorCpfpRbf = {
      val notFundedTx = Transaction(2, Nil, TxOut(1000 sat, Script.pay2wpkh(randomKey().publicKey)) :: Nil, 0)
      bitcoinClient.fundTransaction(notFundedTx, FundTransactionOptions(TestConstants.feeratePerKw * 2)).pipeTo(sender.ref)
      val fundTxResponse = sender.expectMsgType[FundTransactionResponse]
      val unsignedTx = fundTxResponse.tx.copy(txIn = TxIn(OutPoint(commitTx, 1), Nil, 0) +: fundTxResponse.tx.txIn)
      val redeemScript = Script.write(Scripts.anchor(fundingPrivKey.publicKey))
      val sig = Transaction.signInput(unsignedTx, inputIndex = 0, redeemScript, SIGHASH_ALL, anchorAmount, SIGVERSION_WITNESS_V0, fundingPrivKey)
      val anchorWitness = Scripts.witnessAnchor(Crypto.der2compact(sig), redeemScript)
      val partiallySignedTx = unsignedTx.updateWitness(0, anchorWitness)
      bitcoinClient.signTransaction(partiallySignedTx, Nil).pipeTo(sender.ref)
      sender.expectMsgType[SignTransactionResponse].tx
    }

    bitcoinClient.publishTransaction(anchorCpfpRbf).pipeTo(sender.ref)
    sender.expectMsg(anchorCpfpRbf.txid)

    {
      bitcoinClient.getMempool().pipeTo(sender.ref)
      val mempoolTxs = sender.expectMsgType[Seq[Transaction]]
      assert(mempoolTxs.length === 2)
      assert(mempoolTxs.map(_.txid).toSet === Set(commitTx.txid, anchorCpfpRbf.txid))
    }
  }

  case class CommitTxs(alicePrivKey: PrivateKey, bobPrivKey: PrivateKey, commitTxA: Transaction, commitTxB: Transaction)

  case class PackageRbfFixture(alicePrivKey: PrivateKey, bobPrivKey: PrivateKey, commitTxA: Transaction, commitTxB: Transaction, bitcoinClient: BitcoinCoreClient, probe: TestProbe) {
    def createUnconfirmedTx(amount: Satoshi, recipient: PublicKey, feerate: FeeratePerKw): Transaction = {
      val notFunded = Transaction(2, Nil, TxOut(amount, Script.pay2wpkh(recipient)) :: Nil, 0)
      bitcoinClient.fundTransaction(notFunded, FundTransactionOptions(feerate, changePosition = Some(1))).pipeTo(probe.ref)
      bitcoinClient.signTransaction(probe.expectMsgType[FundTransactionResponse].tx).pipeTo(probe.ref)
      val signedTx = probe.expectMsgType[SignTransactionResponse].tx
      bitcoinClient.publishTransaction(signedTx).pipeTo(probe.ref)
      probe.expectMsg(signedTx.txid)
      signedTx
    }

    def createUnconfirmedChain(amount: Satoshi, recipient: PublicKey, feerate: FeeratePerKw): (Transaction, Transaction) = {
      val priv = randomKey()
      val fee = weight2fee(feerate, 570)
      val tx1 = createUnconfirmedTx(amount + fee, priv.publicKey, feerate)
      val tx2 = Transaction(2, Seq(TxIn(OutPoint(tx1, 0), Nil, 0)), Seq(TxOut(amount, Script.pay2wpkh(recipient))), 0)
      val sig = Transaction.signInput(tx2, 0, Script.pay2pkh(priv.publicKey), SIGHASH_ALL, amount + fee, SIGVERSION_WITNESS_V0, priv)
      val signedTx = tx2.updateWitness(0, Script.witnessPay2wpkh(priv.publicKey, sig))
      bitcoinClient.publishTransaction(signedTx).pipeTo(probe.ref)
      probe.expectMsg(signedTx.txid)
      (tx1, signedTx)
    }
  }

  def createPackageRbfFixture(): PackageRbfFixture = {
    val probe = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)
    val commitTxs = createCommitTxs(bitcoinClient, probe)
    PackageRbfFixture(commitTxs.alicePrivKey, commitTxs.bobPrivKey, commitTxs.commitTxA, commitTxs.commitTxB, bitcoinClient, probe)
  }

  def createCommitTxs(bitcoinClient: BitcoinCoreClient, probe: TestProbe): CommitTxs = {
    val (alicePrivKey, bobPrivKey) = (randomKey(), randomKey())
    println(s"A's private key = ${alicePrivKey.toHex}")
    println(s"A's public key = ${alicePrivKey.publicKey.toHex}")
    println(s"B's private key = ${bobPrivKey.toHex}")
    println(s"B's public key = ${bobPrivKey.publicKey.toHex}")
    val fundingAmount = 500_660 sat
    val fundingScript = Scripts.multiSig2of2(alicePrivKey.publicKey, bobPrivKey.publicKey)
    val fundingTx = {
      val notFunded = Transaction(2, Nil, Seq(TxOut(fundingAmount, Script.write(Script.pay2wsh(fundingScript)))), 0)
      bitcoinClient.fundTransaction(notFunded, FundTransactionOptions(TestConstants.feeratePerKw, changePosition = Some(1))).pipeTo(probe.ref)
      bitcoinClient.signTransaction(probe.expectMsgType[FundTransactionResponse].tx).pipeTo(probe.ref)
      val signedTx = probe.expectMsgType[SignTransactionResponse].tx
      bitcoinClient.publishTransaction(signedTx).pipeTo(probe.ref)
      probe.expectMsg(signedTx.txid)
      generateBlocks(1)
      signedTx
    }

    // We create concurrent txs that look like simplified commitment transactions and pay no fees.
    // The first input is always Alice's anchor, the second inputs is always Bob's anchor.
    val (commitTxA, commitTxB) = {
      val dummyCommitTx = Transaction(2, Seq(TxIn(OutPoint(fundingTx, 0), Nil, 0)), Nil, 0)
      val commitTxA = dummyCommitTx.copy(txOut = Seq(
        TxOut(330 sat, Script.pay2wsh(Scripts.anchor(alicePrivKey.publicKey))),
        TxOut(330 sat, Script.pay2wsh(Scripts.anchor(bobPrivKey.publicKey))),
        TxOut(400_000 sat, Script.pay2wsh(Scripts.toRemoteDelayed(alicePrivKey.publicKey))),
        TxOut(100_000 sat, Script.pay2wsh(Scripts.toRemoteDelayed(bobPrivKey.publicKey))),
      ))
      val commitTxB = dummyCommitTx.copy(txOut = Seq(
        TxOut(330 sat, Script.pay2wsh(Scripts.anchor(alicePrivKey.publicKey))),
        TxOut(330 sat, Script.pay2wsh(Scripts.anchor(bobPrivKey.publicKey))),
        TxOut(100_000 sat, Script.pay2wsh(Scripts.toRemoteDelayed(alicePrivKey.publicKey))),
        TxOut(400_000 sat, Script.pay2wsh(Scripts.toRemoteDelayed(bobPrivKey.publicKey))),
      ))
      (commitTxA, commitTxB)
    }

    val aliceSigA = Transaction.signInput(commitTxA, 0, fundingScript, SIGHASH_ALL, fundingAmount, SIGVERSION_WITNESS_V0, alicePrivKey)
    val bobSigA = Transaction.signInput(commitTxA, 0, fundingScript, SIGHASH_ALL, fundingAmount, SIGVERSION_WITNESS_V0, bobPrivKey)
    val witnessA = Scripts.witness2of2(der2compact(aliceSigA), der2compact(bobSigA), alicePrivKey.publicKey, bobPrivKey.publicKey)
    val signedCommitTxA = commitTxA.updateWitness(0, witnessA)
    Transaction.correctlySpends(signedCommitTxA, Seq(fundingTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val aliceSigB = Transaction.signInput(commitTxB, 0, fundingScript, SIGHASH_ALL, fundingAmount, SIGVERSION_WITNESS_V0, alicePrivKey)
    val bobSigB = Transaction.signInput(commitTxB, 0, fundingScript, SIGHASH_ALL, fundingAmount, SIGVERSION_WITNESS_V0, bobPrivKey)
    val witnessB = Scripts.witness2of2(der2compact(aliceSigB), der2compact(bobSigB), alicePrivKey.publicKey, bobPrivKey.publicKey)
    val signedCommitTxB = commitTxB.updateWitness(0, witnessB)
    Transaction.correctlySpends(signedCommitTxB, Seq(fundingTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    println(s"CommitTxA = ${signedCommitTxA.toString()}")
    println(s"CommitTxB = ${signedCommitTxB.toString()}")
    println(s"  Input: amount = $fundingAmount, script = ${Script.write(Script.pay2wsh(fundingScript)).toHex} (p2wsh(multisig2of2(${alicePrivKey.publicKey.toHex}, ${bobPrivKey.publicKey.toHex}))")

    CommitTxs(alicePrivKey, bobPrivKey, signedCommitTxA, signedCommitTxB)
  }

  test("package-rbf #1") {
    println("----- Generating CommitTxA and CommitTxB -----")
    val f = createPackageRbfFixture()
    import f._

    // Mempool #1:
    //
    // +-----------+  +-----------+
    // | CommitTxA |  | ChangeTxA |
    // +-----------+  +-----------+
    //       |              |
    //       +-----+  +-----+
    //             |  |
    //             v  v
    //         +-----------+
    //         | AnchorTxA |
    //         +-----------+
    val changeTxA = f.createUnconfirmedTx(100_000 sat, alicePrivKey.publicKey, FeeratePerKw(500 sat))
    val anchorTxA = {
      val unsignedTx = Transaction(2, Seq(TxIn(OutPoint(commitTxA, 0), Nil, 0), TxIn(OutPoint(changeTxA, 0), Nil, 0)), Seq(TxOut(99_000 sat, Script.pay2wpkh(randomKey().publicKey))), 0)
      val sig0 = Transaction.signInput(unsignedTx, 0, Scripts.anchor(alicePrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, alicePrivKey)
      val sig1 = Transaction.signInput(unsignedTx, 1, Script.pay2pkh(alicePrivKey.publicKey), SIGHASH_ALL, 100_000 sat, SIGVERSION_WITNESS_V0, alicePrivKey)
      unsignedTx
        .updateWitness(0, Scripts.witnessAnchor(der2compact(sig0), Script.write(Scripts.anchor(alicePrivKey.publicKey))))
        .updateWitness(1, Script.witnessPay2wpkh(alicePrivKey.publicKey, sig1))
    }
    Transaction.correctlySpends(anchorTxA, Seq(commitTxA, changeTxA), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    println(s"ChangeTxA = ${changeTxA.toString()}")
    println(s"  Output: amount = ${100_000 sat}, script = ${Script.write(Script.pay2wpkh(alicePrivKey.publicKey)).toHex} (p2wpkh(${alicePrivKey.publicKey.toHex}))")
    println(s"AnchorTxA = ${anchorTxA.toString()}")

    // NB: we must include all unconfirmed parents in the package, even if they're already in the mempool.
    bitcoinClient.publishPackage(Seq(commitTxA, anchorTxA)).pipeTo(probe.ref)
    probe.expectMsgType[Failure]

    bitcoinClient.publishPackage(Seq(commitTxA, changeTxA, anchorTxA)).pipeTo(probe.ref)
    assert(probe.expectMsgType[Seq[ByteVector32]].toSet == Set(commitTxA.txid, changeTxA.txid, anchorTxA.txid))

    bitcoinClient.getMempoolTx(commitTxA.txid).pipeTo(probe.ref)
    assert(probe.expectMsgType[MempoolTx].fees == 0.sat)

    bitcoinClient.getMempoolTx(anchorTxA.txid).pipeTo(probe.ref)
    assert(probe.expectMsgType[MempoolTx].ancestorCount == 2)

    // Mempool #2:
    //
    // +-----------+  +-----------+
    // | CommitTxB |  | ChangeTxB |
    // +-----------+  +-----------+
    //       |              |
    //       +-----+  +-----+
    //             |  |
    //             v  v
    //         +-----------+
    //         | AnchorTxB |
    //         +-----------+
    val changeTxB = f.createUnconfirmedTx(100_000 sat, bobPrivKey.publicKey, FeeratePerKw(500 sat))
    val anchorTxB = {
      val unsignedTx = Transaction(2, Seq(TxIn(OutPoint(commitTxB, 1), Nil, 0), TxIn(OutPoint(changeTxB, 0), Nil, 0)), Seq(TxOut(98_000 sat, Script.pay2wpkh(randomKey().publicKey))), 0)
      val sig0 = Transaction.signInput(unsignedTx, 0, Scripts.anchor(bobPrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, bobPrivKey)
      val sig1 = Transaction.signInput(unsignedTx, 1, Script.pay2pkh(bobPrivKey.publicKey), SIGHASH_ALL, 100_000 sat, SIGVERSION_WITNESS_V0, bobPrivKey)
      unsignedTx
        .updateWitness(0, Scripts.witnessAnchor(der2compact(sig0), Script.write(Scripts.anchor(bobPrivKey.publicKey))))
        .updateWitness(1, Script.witnessPay2wpkh(bobPrivKey.publicKey, sig1))
    }
    Transaction.correctlySpends(anchorTxB, Seq(commitTxB, changeTxB), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    println(s"ChangeTxB = ${changeTxB.toString()}")
    println(s"  Output: amount = ${100_000 sat}, script = ${Script.write(Script.pay2wpkh(bobPrivKey.publicKey)).toHex} (p2wpkh(${bobPrivKey.publicKey.toHex}))")
    println(s"AnchorTxB = ${anchorTxB.toString()}")

    // This is a "basic" package-rbf: this should replace the previous package.
    bitcoinClient.publishPackage(Seq(commitTxB, changeTxB, anchorTxB)).pipeTo(probe.ref)
    assert(probe.expectMsgType[Seq[ByteVector32]].toSet == Set(commitTxB.txid, changeTxB.txid, anchorTxB.txid))

    bitcoinClient.getMempoolTx(commitTxB.txid).pipeTo(probe.ref)
    assert(probe.expectMsgType[MempoolTx].fees == 0.sat)

    bitcoinClient.getMempoolTx(anchorTxB.txid).pipeTo(probe.ref)
    assert(probe.expectMsgType[MempoolTx].ancestorCount == 2)

    bitcoinClient.getMempoolTx(commitTxA.txid).pipeTo(probe.ref)
    probe.expectMsgType[Failure]

    bitcoinClient.getMempoolTx(anchorTxA.txid).pipeTo(probe.ref)
    probe.expectMsgType[Failure]

    bitcoinClient.getMempoolTx(changeTxA.txid).pipeTo(probe.ref)
    assert(probe.expectMsgType[MempoolTx].fees > 0.sat)
  }

  test("package-rbf #2") {
    val f = createPackageRbfFixture()
    import f._

    // Mempool #1:
    //
    // +-----------+  +-----------+
    // | CommitTxA |  | ChangeTxA |
    // +-----------+  +-----------+
    //       |              |
    //       +-----+  +-----+
    //             |  |
    //             v  v
    //         +-----------+
    //         | AnchorTxA |
    //         +-----------+
    val changeTxA = f.createUnconfirmedTx(100_000 sat, alicePrivKey.publicKey, FeeratePerKw(5000 sat))
    val anchorTxA = {
      val unsignedTx = Transaction(2, Seq(TxIn(OutPoint(commitTxA, 0), Nil, 0), TxIn(OutPoint(changeTxA, 0), Nil, 0)), Seq(TxOut(99_000 sat, Script.pay2wpkh(randomKey().publicKey))), 0)
      val sig0 = Transaction.signInput(unsignedTx, 0, Scripts.anchor(alicePrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, alicePrivKey)
      val sig1 = Transaction.signInput(unsignedTx, 1, Script.pay2pkh(alicePrivKey.publicKey), SIGHASH_ALL, 100_000 sat, SIGVERSION_WITNESS_V0, alicePrivKey)
      unsignedTx
        .updateWitness(0, Scripts.witnessAnchor(der2compact(sig0), Script.write(Scripts.anchor(alicePrivKey.publicKey))))
        .updateWitness(1, Script.witnessPay2wpkh(alicePrivKey.publicKey, sig1))
    }
    Transaction.correctlySpends(anchorTxA, Seq(commitTxA, changeTxA), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    bitcoinClient.publishPackage(Seq(commitTxA, changeTxA, anchorTxA)).pipeTo(probe.ref)
    assert(probe.expectMsgType[Seq[ByteVector32]].toSet == Set(commitTxA.txid, changeTxA.txid, anchorTxA.txid))

    // Mempool #2:
    //
    // +-----------+  +-----------+
    // | CommitTxB |  | ChangeTxB |
    // +-----------+  +-----------+
    //       |              |
    //       +-----+  +-----+
    //             |  |
    //             v  v
    //         +-----------+
    //         | AnchorTxB |
    //         +-----------+
    //
    // But here ChangeTxB has a lower feerate than ChangeTxA.
    val changeTxB = f.createUnconfirmedTx(100_000 sat, bobPrivKey.publicKey, FeeratePerKw(500 sat))
    val anchorTxB = {
      val unsignedTx = Transaction(2, Seq(TxIn(OutPoint(commitTxB, 1), Nil, 0), TxIn(OutPoint(changeTxB, 0), Nil, 0)), Seq(TxOut(98_000 sat, Script.pay2wpkh(randomKey().publicKey))), 0)
      val sig0 = Transaction.signInput(unsignedTx, 0, Scripts.anchor(bobPrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, bobPrivKey)
      val sig1 = Transaction.signInput(unsignedTx, 1, Script.pay2pkh(bobPrivKey.publicKey), SIGHASH_ALL, 100_000 sat, SIGVERSION_WITNESS_V0, bobPrivKey)
      unsignedTx
        .updateWitness(0, Scripts.witnessAnchor(der2compact(sig0), Script.write(Scripts.anchor(bobPrivKey.publicKey))))
        .updateWitness(1, Script.witnessPay2wpkh(bobPrivKey.publicKey, sig1))
    }
    Transaction.correctlySpends(anchorTxB, Seq(commitTxB, changeTxB), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // Since we're not replacing ChangeTxA, and [CommitTxB, AnchorTxB] is better than [CommitTxA, AnchorTxA], the replacement
    // should be accepted.
    bitcoinClient.publishPackage(Seq(commitTxB, changeTxB, anchorTxB)).pipeTo(probe.ref)
    assert(probe.expectMsgType[Seq[ByteVector32]].toSet == Set(commitTxB.txid, changeTxB.txid, anchorTxB.txid))

    bitcoinClient.getMempoolTx(commitTxB.txid).pipeTo(probe.ref)
    assert(probe.expectMsgType[MempoolTx].fees == 0.sat)
  }

  test("package-rbf #3") {
    val f = createPackageRbfFixture()
    import f._

    println("----- Generating CommitTxA1 and CommitTxB1 -----")
    val c1 = createCommitTxs(bitcoinClient, probe)
    println("----- Generating CommitTxA2 and CommitTxB2 -----")
    val c2 = createCommitTxs(bitcoinClient, probe)
    println("----- Generating CommitTxA3 and CommitTxB3 -----")
    val c3 = createCommitTxs(bitcoinClient, probe)

    // Mempool #1:
    //
    // +------------+  +------------+  +------------+  +-----------+
    // | CommitTxA1 |  | CommitTxA2 |  | CommitTxA3 |  | ChangeTxA |
    // +------------+  +------------+  +------------+  +-----------+
    //       |              |              |                 |
    //       +-----------+  |  +-----------+                 |
    //                   |  |  |  +--------------------------+
    //                   |  |  |  |
    //                   v  v  v  v
    //                 +-----------+
    //                 | AnchorTxA |
    //                 +-----------+
    val changeTxA = f.createUnconfirmedTx(100_000 sat, alicePrivKey.publicKey, FeeratePerKw(2500 sat))
    val anchorTxA = {
      val inputs = Seq(c1, c2, c3).map(c => TxIn(OutPoint(c.commitTxA, 0), Nil, 0)) :+ TxIn(OutPoint(changeTxA, 0), Nil, 0)
      val unsignedTx = Transaction(2, inputs, Seq(TxOut(98_000 sat, Script.pay2wpkh(randomKey().publicKey))), 0)
      val sig0 = Transaction.signInput(unsignedTx, 0, Scripts.anchor(c1.alicePrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, c1.alicePrivKey)
      val sig1 = Transaction.signInput(unsignedTx, 1, Scripts.anchor(c2.alicePrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, c2.alicePrivKey)
      val sig2 = Transaction.signInput(unsignedTx, 2, Scripts.anchor(c3.alicePrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, c3.alicePrivKey)
      val sig3 = Transaction.signInput(unsignedTx, 3, Script.pay2pkh(alicePrivKey.publicKey), SIGHASH_ALL, 100_000 sat, SIGVERSION_WITNESS_V0, alicePrivKey)
      unsignedTx
        .updateWitness(0, Scripts.witnessAnchor(der2compact(sig0), Script.write(Scripts.anchor(c1.alicePrivKey.publicKey))))
        .updateWitness(1, Scripts.witnessAnchor(der2compact(sig1), Script.write(Scripts.anchor(c2.alicePrivKey.publicKey))))
        .updateWitness(2, Scripts.witnessAnchor(der2compact(sig2), Script.write(Scripts.anchor(c3.alicePrivKey.publicKey))))
        .updateWitness(3, Script.witnessPay2wpkh(alicePrivKey.publicKey, sig3))
    }
    Transaction.correctlySpends(anchorTxA, Seq(c1.commitTxA, c2.commitTxA, c3.commitTxA, changeTxA), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    bitcoinClient.publishPackage(Seq(c1.commitTxA, c2.commitTxA, c3.commitTxA, changeTxA, anchorTxA)).pipeTo(probe.ref)
    assert(probe.expectMsgType[Seq[ByteVector32]].toSet == Set(c1.commitTxA.txid, c2.commitTxA.txid, c3.commitTxA.txid, changeTxA.txid, anchorTxA.txid))

    println(s"ChangeTxA = ${changeTxA.toString()}")
    println(s"  Output: amount = ${100_000 sat}, script = ${Script.write(Script.pay2wpkh(alicePrivKey.publicKey)).toHex} (p2wpkh(${alicePrivKey.publicKey.toHex}))")
    println(s"AnchorTxA = ${anchorTxA.toString()}")

    // Mempool #2:
    //                 +------------+
    //                 | ChangeTxB1 |
    //                 +------------+
    //                       |
    //                       v
    // +------------+  +------------+
    // | CommitTxB1 |  | ChangeTxB2 |
    // +------------+  +------------+
    //       |               |
    //       +----+  +-------+
    //            |  |
    //            v  v
    //        +-----------+
    //        | AnchorTxB |
    //        +-----------+
    val (changeTxB1, changeTxB2) = f.createUnconfirmedChain(50_000 sat, bobPrivKey.publicKey, FeeratePerKw(1000 sat))
    val anchorTxB = {
      val unsignedTx = Transaction(2, Seq(TxIn(OutPoint(c1.commitTxB, 1), Nil, 0), TxIn(OutPoint(changeTxB2, 0), Nil, 0)), Seq(TxOut(45_000 sat, Script.pay2wpkh(randomKey().publicKey))), 0)
      val sig0 = Transaction.signInput(unsignedTx, 0, Scripts.anchor(c1.bobPrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, c1.bobPrivKey)
      val sig1 = Transaction.signInput(unsignedTx, 1, Script.pay2pkh(bobPrivKey.publicKey), SIGHASH_ALL, 50_000 sat, SIGVERSION_WITNESS_V0, bobPrivKey)
      unsignedTx
        .updateWitness(0, Scripts.witnessAnchor(der2compact(sig0), Script.write(Scripts.anchor(c1.bobPrivKey.publicKey))))
        .updateWitness(1, Script.witnessPay2wpkh(bobPrivKey.publicKey, sig1))
    }
    Transaction.correctlySpends(anchorTxB, Seq(c1.commitTxB, changeTxB2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    println(s"ChangeTxB1 = ${changeTxB1.toString()}")
    println(s"ChangeTxB2 = ${changeTxB2.toString()}")
    println(s"  Output: amount = ${50_000 sat}, script = ${Script.write(Script.pay2wpkh(bobPrivKey.publicKey)).toHex} (p2wpkh(${bobPrivKey.publicKey.toHex}))")
    println(s"AnchorTxB = ${anchorTxB.toString()}")

    bitcoinClient.publishPackage(Seq(c1.commitTxB, changeTxB2, anchorTxB)).pipeTo(probe.ref)
    assert(probe.expectMsgType[Seq[ByteVector32]].toSet == Set(c1.commitTxB.txid, changeTxB2.txid, anchorTxB.txid))

    bitcoinClient.getMempoolTx(c1.commitTxB.txid).pipeTo(probe.ref)
    assert(probe.expectMsgType[MempoolTx].fees == 0.sat)

    // The conflicting commit tx and its anchor are evicted.
    Seq(c1.commitTxA, anchorTxA).foreach(tx => {
      bitcoinClient.getMempoolTx(tx.txid).pipeTo(probe.ref)
      probe.expectMsgType[Failure]
    })

    // But the other commit txs are not evicted, even though they pay 0 fees.
    Seq(c2.commitTxA, c3.commitTxA).foreach(tx => {
      bitcoinClient.getMempoolTx(tx.txid).pipeTo(probe.ref)
      probe.expectMsgType[MempoolTx]
    })
  }

  test("package-rbf #4") {
    val f = createPackageRbfFixture()
    import f._

    println("----- Generating CommitTxA1 and CommitTxB1 -----")
    val c1 = createCommitTxs(bitcoinClient, probe)
    println("----- Generating CommitTxA2 and CommitTxB2 -----")
    val c2 = createCommitTxs(bitcoinClient, probe)
    println("----- Generating CommitTxA3 and CommitTxB3 -----")
    val c3 = createCommitTxs(bitcoinClient, probe)

    // Mempool #1:
    //
    // +------------+  +------------+  +------------+  +------------+
    // | CommitTxA1 |  | CommitTxA2 |  | CommitTxA3 |  | ChangeTxA1 |
    // +------------+  +------------+  +------------+  +------------+
    //       |              |              |                 |
    //       +-----------+  |  +-----------+                 |
    //                   |  |  |  +--------------------------+
    //                   |  |  |  |
    //                   v  v  v  v
    //                 +------------+
    //                 | AnchorTxA1 |
    //                 +------------+
    val changeTxA1 = f.createUnconfirmedTx(100_000 sat, alicePrivKey.publicKey, FeeratePerKw(2500 sat))
    val anchorTxA1 = {
      val inputs = Seq(c1, c2, c3).map(c => TxIn(OutPoint(c.commitTxA, 0), Nil, 0)) :+ TxIn(OutPoint(changeTxA1, 0), Nil, 0)
      val unsignedTx = Transaction(2, inputs, Seq(TxOut(98_000 sat, Script.pay2wpkh(randomKey().publicKey))), 0)
      val sig0 = Transaction.signInput(unsignedTx, 0, Scripts.anchor(c1.alicePrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, c1.alicePrivKey)
      val sig1 = Transaction.signInput(unsignedTx, 1, Scripts.anchor(c2.alicePrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, c2.alicePrivKey)
      val sig2 = Transaction.signInput(unsignedTx, 2, Scripts.anchor(c3.alicePrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, c3.alicePrivKey)
      val sig3 = Transaction.signInput(unsignedTx, 3, Script.pay2pkh(alicePrivKey.publicKey), SIGHASH_ALL, 100_000 sat, SIGVERSION_WITNESS_V0, alicePrivKey)
      unsignedTx
        .updateWitness(0, Scripts.witnessAnchor(der2compact(sig0), Script.write(Scripts.anchor(c1.alicePrivKey.publicKey))))
        .updateWitness(1, Scripts.witnessAnchor(der2compact(sig1), Script.write(Scripts.anchor(c2.alicePrivKey.publicKey))))
        .updateWitness(2, Scripts.witnessAnchor(der2compact(sig2), Script.write(Scripts.anchor(c3.alicePrivKey.publicKey))))
        .updateWitness(3, Script.witnessPay2wpkh(alicePrivKey.publicKey, sig3))
    }
    Transaction.correctlySpends(anchorTxA1, Seq(c1.commitTxA, c2.commitTxA, c3.commitTxA, changeTxA1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    bitcoinClient.publishPackage(Seq(c1.commitTxA, c2.commitTxA, c3.commitTxA, changeTxA1, anchorTxA1)).pipeTo(probe.ref)
    assert(probe.expectMsgType[Seq[ByteVector32]].toSet == Set(c1.commitTxA.txid, c2.commitTxA.txid, c3.commitTxA.txid, changeTxA1.txid, anchorTxA1.txid))

    println(s"ChangeTxA1 = ${changeTxA1.toString()}")
    println(s"  Output: amount = ${100_000 sat}, script = ${Script.write(Script.pay2wpkh(alicePrivKey.publicKey)).toHex} (p2wpkh(${alicePrivKey.publicKey.toHex}))")
    println(s"AnchorTxA1 = ${anchorTxA1.toString()}")

    // Mempool #2:
    //                                 +------------+
    //                                 | ChangeTxA2 |
    //                                 +------------+
    //                                       |
    //                                       v
    // +------------+  +------------+  +------------+
    // | CommitTxA1 |  | CommitTxA4 |  | ChangeTxA3 |
    // +------------+  +------------+  +------------+
    //       |              |                |
    //       +---+  +-------+                |
    //           |  |  +---------------------+
    //           |  |  |
    //           v  v  v
    //        +------------+
    //        | AnchorTxA2 |
    //        +------------+
    println("----- Generating CommitTxA4 and CommitTxB4 -----")
    val c4 = createCommitTxs(bitcoinClient, probe)
    val (changeTxA2, changeTxA3) = f.createUnconfirmedChain(50_000 sat, alicePrivKey.publicKey, FeeratePerKw(1000 sat))
    val anchorTxA2 = {
      val unsignedTx = Transaction(2, Seq(TxIn(OutPoint(c1.commitTxA, 0), Nil, 0), TxIn(OutPoint(c4.commitTxA, 0), Nil, 0), TxIn(OutPoint(changeTxA3, 0), Nil, 0)), Seq(TxOut(45_000 sat, Script.pay2wpkh(randomKey().publicKey))), 0)
      val sig0 = Transaction.signInput(unsignedTx, 0, Scripts.anchor(c1.alicePrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, c1.alicePrivKey)
      val sig1 = Transaction.signInput(unsignedTx, 1, Scripts.anchor(c4.alicePrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, c4.alicePrivKey)
      val sig2 = Transaction.signInput(unsignedTx, 2, Script.pay2pkh(alicePrivKey.publicKey), SIGHASH_ALL, 50_000 sat, SIGVERSION_WITNESS_V0, alicePrivKey)
      unsignedTx
        .updateWitness(0, Scripts.witnessAnchor(der2compact(sig0), Script.write(Scripts.anchor(c1.alicePrivKey.publicKey))))
        .updateWitness(1, Scripts.witnessAnchor(der2compact(sig1), Script.write(Scripts.anchor(c4.alicePrivKey.publicKey))))
        .updateWitness(2, Script.witnessPay2wpkh(alicePrivKey.publicKey, sig2))
    }
    Transaction.correctlySpends(anchorTxA2, Seq(c1.commitTxA, c4.commitTxA, changeTxA3), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    println(s"ChangeTxA2 = ${changeTxA2.toString()}")
    println(s"ChangeTxA3 = ${changeTxA3.toString()}")
    println(s"  Output: amount = ${50_000 sat}, script = ${Script.write(Script.pay2wpkh(alicePrivKey.publicKey)).toHex} (p2wpkh(${alicePrivKey.publicKey.toHex}))")
    println(s"AnchorTxA2 = ${anchorTxA2.toString()}")

    // TODO: this test triggers the following error: Internal bug detected: "it != package_result.m_tx_results.end()"
    bitcoinClient.publishPackage(Seq(c1.commitTxA, c4.commitTxA, changeTxA3, anchorTxA2)).pipeTo(probe.ref)
    assert(probe.expectMsgType[Seq[ByteVector32]].toSet == Set(c1.commitTxA.txid, c4.commitTxA.txid, changeTxA3.txid, anchorTxA2.txid))

    // The conflicting anchor is evicted.
    bitcoinClient.getMempoolTx(anchorTxA1.txid).pipeTo(probe.ref)
    probe.expectMsgType[Failure]

    // But the other commit txs are not evicted, even though they pay 0 fees.
    Seq(c1.commitTxA, c2.commitTxA, c3.commitTxA, c4.commitTxA).foreach(tx => {
      bitcoinClient.getMempoolTx(tx.txid).pipeTo(probe.ref)
      assert(probe.expectMsgType[MempoolTx].fees == 0.sat)
    })
  }

  test("package-rbf #5") {
    val f = createPackageRbfFixture()
    import f._

    // Mempool #1:
    //
    // +-----------+  +-----------+
    // | CommitTxA |  | ChangeTxA |
    // +-----------+  +-----------+
    //       |              |
    //       +-----+  +-----+
    //             |  |
    //             v  v
    //         +-----------+
    //         | AnchorTxA |
    //         +-----------+
    //               |
    //              ... low feerate descendants
    //               |
    //               v
    //         +-----------+
    //         |  JunkTxA  | high feerate descendant
    //         +-----------+
    val changeTxA = f.createUnconfirmedTx(1_000_000 sat, alicePrivKey.publicKey, FeeratePerKw(500 sat))
    val anchorTxA = {
      val unsignedTx = Transaction(2, Seq(TxIn(OutPoint(commitTxA, 0), Nil, 0), TxIn(OutPoint(changeTxA, 0), Nil, 0)), Seq(TxOut(999_000 sat, Script.pay2wpkh(alicePrivKey.publicKey))), 0)
      val sig0 = Transaction.signInput(unsignedTx, 0, Scripts.anchor(alicePrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, alicePrivKey)
      val sig1 = Transaction.signInput(unsignedTx, 1, Script.pay2pkh(alicePrivKey.publicKey), SIGHASH_ALL, 1_000_000 sat, SIGVERSION_WITNESS_V0, alicePrivKey)
      unsignedTx
        .updateWitness(0, Scripts.witnessAnchor(der2compact(sig0), Script.write(Scripts.anchor(alicePrivKey.publicKey))))
        .updateWitness(1, Script.witnessPay2wpkh(alicePrivKey.publicKey, sig1))
    }
    Transaction.correctlySpends(anchorTxA, Seq(commitTxA, changeTxA), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    println(s"ChangeTxA = ${changeTxA.toString()}")
    println(s"  Output: amount = ${1_000_000 sat}, script = ${Script.write(Script.pay2wpkh(alicePrivKey.publicKey)).toHex} (p2wpkh(${alicePrivKey.publicKey.toHex}))")
    println(s"AnchorTxA = ${anchorTxA.toString()}")

    bitcoinClient.publishPackage(Seq(commitTxA, changeTxA, anchorTxA)).pipeTo(probe.ref)
    assert(probe.expectMsgType[Seq[ByteVector32]].toSet == Set(commitTxA.txid, changeTxA.txid, anchorTxA.txid))

    bitcoinClient.getMempoolTx(anchorTxA.txid).pipeTo(probe.ref)
    val mempoolAnchorA = probe.expectMsgType[MempoolTx]
    val anchorFeerateA = fee2rate(mempoolAnchorA.fees, mempoolAnchorA.weight.toInt)
    assert(anchorFeerateA <= FeeratePerKw(2500 sat))
    println(s"anchor feerate=$anchorFeerateA")

    // Create a chain of low feerate descendants.
    var lastChild = anchorTxA
    (1 to 21).foreach(i => {
      val currentAmount = lastChild.txOut.head.amount
      // We add outputs to make the tx bigger than the last child while paying a low feerate
      val dummyOutputs = (1 to 10).map(_ => TxOut(1000 sat, Script.pay2pkh(randomKey().publicKey)))
      val nextTx = Transaction(2, Seq(TxIn(OutPoint(lastChild, 0), Nil, 0)), TxOut(currentAmount - 10_500.sat, Script.pay2wpkh(alicePrivKey.publicKey)) +: dummyOutputs, 0)
      val sig = Transaction.signInput(nextTx, 0, Script.pay2pkh(alicePrivKey.publicKey), SIGHASH_ALL, currentAmount, SIGVERSION_WITNESS_V0, alicePrivKey)
      lastChild = nextTx.updateWitness(0, Script.witnessPay2wpkh(alicePrivKey.publicKey, sig))
      println(s"Descendant$i = ${lastChild.toString()}")
      bitcoinClient.publishTransaction(lastChild).pipeTo(probe.ref)
      probe.expectMsg(lastChild.txid)
    })

    // Add a final high feerate descendant.
    {
      val currentAmount = lastChild.txOut.head.amount
      val nextTx = Transaction(2, Seq(TxIn(OutPoint(lastChild, 0), Nil, 0)), Seq(TxOut(currentAmount - 25000.sat, Script.pay2wpkh(alicePrivKey.publicKey))), 0)
      val sig = Transaction.signInput(nextTx, 0, Script.pay2pkh(alicePrivKey.publicKey), SIGHASH_ALL, currentAmount, SIGVERSION_WITNESS_V0, alicePrivKey)
      lastChild = nextTx.updateWitness(0, Script.witnessPay2wpkh(alicePrivKey.publicKey, sig))
      println(s"Last descendant = ${lastChild.toString()}")
      bitcoinClient.publishTransaction(lastChild).pipeTo(probe.ref)
      probe.expectMsg(lastChild.txid)
    }

    bitcoinClient.getMempoolTx(lastChild.txid).pipeTo(probe.ref)
    val mempoolLastChild = probe.expectMsgType[MempoolTx]
    val lastChildFeerate = fee2rate(mempoolLastChild.fees, mempoolLastChild.weight.toInt)
    println(s"high-feerate pinning descendant: feerate=$lastChildFeerate")

    // Mempool #2:
    //
    // +-----------+  +-----------+
    // | CommitTxB |  | ChangeTxB |
    // +-----------+  +-----------+
    //       |              |
    //       +-----+  +-----+
    //             |  |
    //             v  v
    //         +-----------+
    //         | AnchorTxB |
    //         +-----------+
    val changeTxB = f.createUnconfirmedTx(100_000 sat, bobPrivKey.publicKey, FeeratePerKw(500 sat))
    val anchorTxB = {
      val unsignedTx = Transaction(2, Seq(TxIn(OutPoint(commitTxB, 1), Nil, 0), TxIn(OutPoint(changeTxB, 0), Nil, 0)), Seq(TxOut(63_000 sat, Script.pay2wpkh(randomKey().publicKey))), 0)
      val sig0 = Transaction.signInput(unsignedTx, 0, Scripts.anchor(bobPrivKey.publicKey), SIGHASH_ALL, 330 sat, SIGVERSION_WITNESS_V0, bobPrivKey)
      val sig1 = Transaction.signInput(unsignedTx, 1, Script.pay2pkh(bobPrivKey.publicKey), SIGHASH_ALL, 100_000 sat, SIGVERSION_WITNESS_V0, bobPrivKey)
      unsignedTx
        .updateWitness(0, Scripts.witnessAnchor(der2compact(sig0), Script.write(Scripts.anchor(bobPrivKey.publicKey))))
        .updateWitness(1, Script.witnessPay2wpkh(bobPrivKey.publicKey, sig1))
    }
    Transaction.correctlySpends(anchorTxB, Seq(commitTxB, changeTxB), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    println(s"ChangeTxB = ${changeTxB.toString()}")
    println(s"  Output: amount = ${100_000 sat}, script = ${Script.write(Script.pay2wpkh(bobPrivKey.publicKey)).toHex} (p2wpkh(${bobPrivKey.publicKey.toHex}))")
    println(s"AnchorTxB = ${anchorTxB.toString()}")

    bitcoinClient.publishPackage(Seq(commitTxB, changeTxB, anchorTxB)).pipeTo(probe.ref)
    assert(probe.expectMsgType[Seq[ByteVector32]].toSet == Set(commitTxB.txid, changeTxB.txid, anchorTxB.txid))

    // The previous anchor and its descendants are evicted.
    bitcoinClient.getMempoolTx(anchorTxA.txid).pipeTo(probe.ref)
    probe.expectMsgType[Failure]

    // We don't need to match the last descendant's feerate.
    bitcoinClient.getMempoolTx(anchorTxB.txid).pipeTo(probe.ref)
    val mempoolAnchorB = probe.expectMsgType[MempoolTx]
    val anchorFeerateB = fee2rate(mempoolAnchorB.fees, mempoolAnchorB.weight.toInt)
    assert(anchorFeerateA < anchorFeerateB)
    assert(anchorFeerateB < lastChildFeerate)
    println(s"new anchor feerate=$anchorFeerateB")
  }

  test("send and list transactions") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    bitcoinClient.onChainBalance().pipeTo(sender.ref)
    val initialBalance = sender.expectMsgType[OnChainBalance]
    assert(initialBalance.unconfirmed == 0.sat)
    assert(initialBalance.confirmed > 50.btc.toSatoshi)

    val address = "n2YKngjUp139nkjKvZGnfLRN6HzzYxJsje"
    val amount = 150.millibtc.toSatoshi
    bitcoinClient.sendToAddress(address, amount, 3).pipeTo(sender.ref)
    val txid = sender.expectMsgType[ByteVector32]

    bitcoinClient.listTransactions(25, 0).pipeTo(sender.ref)
    val Some(tx1) = sender.expectMsgType[List[WalletTx]].collectFirst { case tx if tx.txid == txid => tx }
    assert(tx1.address == address)
    assert(tx1.amount == -amount)
    assert(tx1.fees < 0.sat)
    assert(tx1.confirmations == 0)

    bitcoinClient.onChainBalance().pipeTo(sender.ref)
    // NB: we use + because these amounts are already negative
    sender.expectMsg(initialBalance.copy(confirmed = initialBalance.confirmed + tx1.amount + tx1.fees))

    generateBlocks(1)
    bitcoinClient.listTransactions(25, 0).pipeTo(sender.ref)
    val Some(tx2) = sender.expectMsgType[List[WalletTx]].collectFirst { case tx if tx.txid == txid => tx }
    assert(tx2.address == address)
    assert(tx2.amount == -amount)
    assert(tx2.fees < 0.sat)
    assert(tx2.confirmations == 1)
  }

  test("get mempool transaction") {
    val sender = TestProbe()
    val address = getNewAddress(sender)
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    def spendWalletTx(tx: Transaction, fees: Satoshi): Transaction = {
      val inputs = tx.txOut.indices.map(vout => Map("txid" -> tx.txid, "vout" -> vout))
      val amount = tx.txOut.map(_.amount).sum - fees
      bitcoinrpcclient.invoke("createrawtransaction", inputs, Map(address -> amount.toBtc.toBigDecimal)).pipeTo(sender.ref)
      val JString(unsignedTx) = sender.expectMsgType[JValue]
      bitcoinClient.signTransaction(Transaction.read(unsignedTx), Nil).pipeTo(sender.ref)
      val signedTx = sender.expectMsgType[SignTransactionResponse].tx
      bitcoinClient.publishTransaction(signedTx).pipeTo(sender.ref)
      sender.expectMsg(signedTx.txid)
      signedTx
    }

    val tx1 = sendToAddress(address, 0.5 btc, sender)
    val tx2 = spendWalletTx(tx1, 5000 sat)
    val tx3 = spendWalletTx(tx2, 7500 sat)

    bitcoinClient.getMempoolTx(tx1.txid).pipeTo(sender.ref)
    val mempoolTx1 = sender.expectMsgType[MempoolTx]
    assert(mempoolTx1.ancestorCount == 0)
    assert(mempoolTx1.descendantCount == 2)
    assert(mempoolTx1.fees == mempoolTx1.ancestorFees)
    assert(mempoolTx1.descendantFees == mempoolTx1.fees + 12500.sat)

    bitcoinClient.getMempoolTx(tx2.txid).pipeTo(sender.ref)
    val mempoolTx2 = sender.expectMsgType[MempoolTx]
    assert(mempoolTx2.ancestorCount == 1)
    assert(mempoolTx2.descendantCount == 1)
    assert(mempoolTx2.fees == 5000.sat)
    assert(mempoolTx2.descendantFees == 12500.sat)
    assert(mempoolTx2.ancestorFees == mempoolTx1.fees + 5000.sat)

    bitcoinClient.getMempoolTx(tx3.txid).pipeTo(sender.ref)
    val mempoolTx3 = sender.expectMsgType[MempoolTx]
    assert(mempoolTx3.ancestorCount == 2)
    assert(mempoolTx3.descendantCount == 0)
    assert(mempoolTx3.fees == 7500.sat)
    assert(mempoolTx3.descendantFees == mempoolTx3.fees)
    assert(mempoolTx3.ancestorFees == mempoolTx1.fees + 12500.sat)
  }

  test("abandon transaction") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    // Broadcast a wallet transaction.
    val opts = FundTransactionOptions(TestConstants.feeratePerKw, changePosition = Some(1))
    bitcoinClient.fundTransaction(Transaction(2, Nil, Seq(TxOut(250000 sat, Script.pay2wpkh(randomKey().publicKey))), 0), opts).pipeTo(sender.ref)
    val fundedTx1 = sender.expectMsgType[FundTransactionResponse].tx
    bitcoinClient.signTransaction(fundedTx1, Nil).pipeTo(sender.ref)
    val signedTx1 = sender.expectMsgType[SignTransactionResponse].tx
    bitcoinClient.publishTransaction(signedTx1).pipeTo(sender.ref)
    sender.expectMsg(signedTx1.txid)

    // Double-spend that transaction.
    val fundedTx2 = fundedTx1.copy(txOut = TxOut(200000 sat, Script.pay2wpkh(randomKey().publicKey)) +: fundedTx1.txOut.tail)
    bitcoinClient.signTransaction(fundedTx2, Nil).pipeTo(sender.ref)
    val signedTx2 = sender.expectMsgType[SignTransactionResponse].tx
    assert(signedTx2.txid != signedTx1.txid)
    bitcoinClient.publishTransaction(signedTx2).pipeTo(sender.ref)
    sender.expectMsg(signedTx2.txid)

    // Abandon the first wallet transaction.
    bitcoinClient.abandonTransaction(signedTx1.txid).pipeTo(sender.ref)
    sender.expectMsg(true)

    // Abandoning an already-abandoned transaction is a no-op.
    bitcoinClient.abandonTransaction(signedTx1.txid).pipeTo(sender.ref)
    sender.expectMsg(true)

    // We can't abandon the second transaction (it's in the mempool).
    bitcoinClient.abandonTransaction(signedTx2.txid).pipeTo(sender.ref)
    sender.expectMsg(false)

    // We can't abandon a confirmed transaction.
    bitcoinClient.abandonTransaction(signedTx2.txIn.head.outPoint.txid).pipeTo(sender.ref)
    sender.expectMsg(false)
  }

  test("detect if tx has been double-spent") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    // first let's create a tx
    val noInputTx1 = Transaction(2, Nil, Seq(TxOut(500_000 sat, Script.pay2wpkh(randomKey().publicKey))), 0)
    bitcoinClient.fundTransaction(noInputTx1, FundTransactionOptions(FeeratePerKw(2500 sat))).pipeTo(sender.ref)
    val unsignedTx1 = sender.expectMsgType[FundTransactionResponse].tx
    bitcoinClient.signTransaction(unsignedTx1).pipeTo(sender.ref)
    val tx1 = sender.expectMsgType[SignTransactionResponse].tx

    // let's then generate another tx that double spends the first one
    val unsignedTx2 = tx1.copy(txOut = Seq(TxOut(tx1.txOut.map(_.amount).sum, Script.pay2wpkh(randomKey().publicKey))))
    bitcoinClient.signTransaction(unsignedTx2).pipeTo(sender.ref)
    val tx2 = sender.expectMsgType[SignTransactionResponse].tx

    // tx1/tx2 haven't been published, so tx1 isn't double-spent
    bitcoinClient.doubleSpent(tx1).pipeTo(sender.ref)
    sender.expectMsg(false)
    // let's publish tx2
    bitcoinClient.publishTransaction(tx2).pipeTo(sender.ref)
    sender.expectMsg(tx2.txid)
    // tx2 hasn't been confirmed so tx1 is still not considered double-spent
    bitcoinClient.doubleSpent(tx1).pipeTo(sender.ref)
    sender.expectMsg(false)
    // tx2 isn't considered double-spent either
    bitcoinClient.doubleSpent(tx2).pipeTo(sender.ref)
    sender.expectMsg(false)
    // let's confirm tx2
    generateBlocks(1)
    // this time tx1 has been double-spent
    bitcoinClient.doubleSpent(tx1).pipeTo(sender.ref)
    sender.expectMsg(true)
    // and tx2 isn't considered double-spent since it's confirmed
    bitcoinClient.doubleSpent(tx2).pipeTo(sender.ref)
    sender.expectMsg(false)
  }

  test("detect if tx has been double-spent (with unconfirmed inputs)") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)
    val priv = randomKey()

    // Let's create one confirmed and one unconfirmed utxo.
    val (confirmedParentTx, unconfirmedParentTx) = {
      val txs = Seq(400_000 sat, 500_000 sat).map(amount => {
        val noInputTx = Transaction(2, Nil, Seq(TxOut(amount, Script.pay2wpkh(priv.publicKey))), 0)
        bitcoinClient.fundTransaction(noInputTx, FundTransactionOptions(FeeratePerKw(2500 sat), lockUtxos = true)).pipeTo(sender.ref)
        val unsignedTx = sender.expectMsgType[FundTransactionResponse].tx
        bitcoinClient.signTransaction(unsignedTx).pipeTo(sender.ref)
        sender.expectMsgType[SignTransactionResponse].tx
      })
      bitcoinClient.publishTransaction(txs.head).pipeTo(sender.ref)
      sender.expectMsg(txs.head.txid)
      generateBlocks(1)
      bitcoinClient.publishTransaction(txs.last).pipeTo(sender.ref)
      sender.expectMsg(txs.last.txid)
      (txs.head, txs.last)
    }

    // Let's spend those unconfirmed utxos.
    val childTx = createSpendManyP2WPKH(Seq(confirmedParentTx, unconfirmedParentTx), priv, priv.publicKey, 500 sat, 0, 0)
    // The tx hasn't been published, so it isn't double-spent.
    bitcoinClient.doubleSpent(childTx).pipeTo(sender.ref)
    sender.expectMsg(false)
    // We publish the tx and verify it isn't double-spent.
    bitcoinClient.publishTransaction(childTx).pipeTo(sender.ref)
    sender.expectMsg(childTx.txid)
    bitcoinClient.doubleSpent(childTx).pipeTo(sender.ref)
    sender.expectMsg(false)

    // We double-spend the unconfirmed parent, which evicts our child transaction.
    {
      val previousAmountOut = unconfirmedParentTx.txOut.map(_.amount).sum
      val unsignedTx = unconfirmedParentTx.copy(txOut = Seq(TxOut(previousAmountOut - 50_000.sat, Script.pay2wpkh(randomKey().publicKey))))
      bitcoinClient.signTransaction(unsignedTx).pipeTo(sender.ref)
      val signedTx = sender.expectMsgType[SignTransactionResponse].tx
      bitcoinClient.publishTransaction(signedTx).pipeTo(sender.ref)
      sender.expectMsg(signedTx.txid)
    }

    // We can't know whether the child transaction is double-spent or not, as its unconfirmed input is now unknown: it's
    // not in the blockchain nor in the mempool. This unknown input may reappear in the future and the tx could then be
    // published again.
    bitcoinClient.doubleSpent(childTx).pipeTo(sender.ref)
    sender.expectMsg(false)

    // We double-spend the confirmed input.
    val spendingTx = createSpendP2WPKH(confirmedParentTx, priv, priv.publicKey, 600 sat, 0, 0)
    bitcoinClient.publishTransaction(spendingTx).pipeTo(sender.ref)
    sender.expectMsg(spendingTx.txid)
    // While the spending transaction is unconfirmed, we don't consider our transaction double-spent.
    bitcoinClient.doubleSpent(childTx).pipeTo(sender.ref)
    sender.expectMsg(false)
    // Once the spending transaction confirms, we know that our transaction is double-spent.
    generateBlocks(1)
    bitcoinClient.doubleSpent(childTx).pipeTo(sender.ref)
    sender.expectMsg(true)
  }

  test("find spending transaction of a given output") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    bitcoinClient.getBlockHeight().pipeTo(sender.ref)
    val blockHeight = sender.expectMsgType[BlockHeight]

    val address = getNewAddress(sender)
    val tx1 = sendToAddress(address, 5 btc, sender)

    // Transaction is still in the mempool at that point
    bitcoinClient.getTxConfirmations(tx1.txid).pipeTo(sender.ref)
    sender.expectMsg(Some(0))
    // If we omit the mempool, tx1's input is still considered unspent.
    bitcoinClient.isTransactionOutputSpendable(tx1.txIn.head.outPoint.txid, tx1.txIn.head.outPoint.index.toInt, includeMempool = false).pipeTo(sender.ref)
    sender.expectMsg(true)
    // If we include the mempool, we see that tx1's input is now spent.
    bitcoinClient.isTransactionOutputSpendable(tx1.txIn.head.outPoint.txid, tx1.txIn.head.outPoint.index.toInt, includeMempool = true).pipeTo(sender.ref)
    sender.expectMsg(false)
    // If we omit the mempool, tx1's output is not considered spendable because we can't even find that output.
    bitcoinClient.isTransactionOutputSpendable(tx1.txid, 0, includeMempool = false).pipeTo(sender.ref)
    sender.expectMsg(false)
    // If we include the mempool, we see that tx1 produces an output that is still unspent.
    bitcoinClient.isTransactionOutputSpendable(tx1.txid, 0, includeMempool = true).pipeTo(sender.ref)
    sender.expectMsg(true)

    // Let's confirm our transaction.
    generateBlocks(1)
    bitcoinClient.getBlockHeight().pipeTo(sender.ref)
    val blockHeight1 = sender.expectMsgType[BlockHeight]
    assert(blockHeight1 == blockHeight + 1)
    bitcoinClient.getTxConfirmations(tx1.txid).pipeTo(sender.ref)
    sender.expectMsg(Some(1))
    bitcoinClient.isTransactionOutputSpendable(tx1.txid, 0, includeMempool = false).pipeTo(sender.ref)
    sender.expectMsg(true)
    bitcoinClient.isTransactionOutputSpendable(tx1.txid, 0, includeMempool = true).pipeTo(sender.ref)
    sender.expectMsg(true)

    generateBlocks(1)
    bitcoinClient.lookForSpendingTx(None, tx1.txIn.head.outPoint.txid, tx1.txIn.head.outPoint.index.toInt).pipeTo(sender.ref)
    sender.expectMsg(tx1)
  }

  test("compute pubkey from a receive address") {
    val sender = TestProbe()
    val bitcoinClient = new BitcoinCoreClient(bitcoinrpcclient)

    bitcoinClient.getReceiveAddress().pipeTo(sender.ref)
    val address = sender.expectMsgType[String]

    bitcoinClient.getReceivePubkey(receiveAddress = Some(address)).pipeTo(sender.ref)
    val receiveKey = sender.expectMsgType[PublicKey]
    assert(addressToPublicKeyScript(address, Block.RegtestGenesisBlock.hash) == Script.pay2wpkh(receiveKey))
  }

}