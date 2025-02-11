/*
 * Copyright 2020 ACINQ SAS
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

package fr.acinq.bitcoin

import fr.acinq.bitcoin.SigHash.SIGHASH_ALL
import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

class TransactionTestsCommon {

    @Test
    fun `read empty transaction`() {
        val tx = Transaction.read("02000000000000000000")
        assertEquals(tx, Transaction(2, listOf(), listOf(), 0))
    }

    @Test
    fun `read and write transactions`() {
        val hex =
            "0100000003864d5e5ec82c9e6f4ac52b8fa47b77f8616bbc26fcf668432c097c5add169584010000006a47304402203be0cff1faacadce3b02d615a8ac15532f9a90bd30e109eaa3e01bfa3a97d90b0220355f3bc382e35b9cae24e5d674f200b289bb948675ce1b5c931029ccb23ae836012102fd18c2a069488288ae93c2157dff3fd657a39426e8753512a5547f046b4a2cbbffffffffd587b10688e6d56225dd4dc488b74229a353e4613cbe1deadaef52b56616baa9000000008b483045022100ab98145e8526b32e821beeaed41a98da68c3c75ee13c477ee0e3d66a626217e902204d015af2e7dba834bbe421dd0b1353a1060dafee58c284dd763e07639858f9340141043ca81d9fe7996372eb21b2588af07c7fbdb6d4fc1da13aaf953c520ba1da4f87d53dfcba3525369fdb248e60233fdf6df0a8183a6dd5699c9a6f5c537367c627ffffffff94a162b4aab080a09fa982a5d7f586045ba2a4c653c98ff47b952d43c25b45fd000000008a47304402200e0c0223d169282a48731b58ff0673c00205deb3f3f4f28d99b50730ada1571402202fa9f051762d8e0199791ea135df1f393578c1eea530bec00fa16f6bba7e3aa3014104626f9b06c44bcfd5d2f6bdeab456591287e2d2b2e299815edf0c9fd0f23c21364ed5dbe97c9c6e2be40fff40c31f8561a9dee015146fe59ecf68b8a377292c72ffffffff02c0c62d00000000001976a914e410e8bc694e8a39c32a273eb1d71930f63648fe88acc0cf6a00000000001976a914324505870d6f21dca7d2f90642cd9603553f6fa688ac00000000"
        val tx = Transaction.read(hex)
        assertEquals(hex, Hex.encode(Transaction.write(tx)))
    }

    @Test
    fun `read transaction without inputs in non-witness format`() {
        val hex = "020000000002d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300"
        assertFails { Transaction.read(hex) }
        val tx = Transaction.read(hex, Protocol.PROTOCOL_VERSION or Transaction.SERIALIZE_TRANSACTION_NO_WITNESS)
        assertEquals(tx.version, 2)
        assertTrue(tx.txIn.isEmpty())
        assertEquals(tx.txid, ByteVector32("062d74b3c6183147c30a02addf3c8cd0df10a049ced5677247edd8f114ddb6fb"))
        assertEquals(tx.txOut.size, 2)
        assertEquals(tx.txOut[0].publicKeyScript, ByteVector(Script.write(listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(ByteVector("d0c59903c5bac2868760e90fd521a4665aa76520")), OP_EQUALVERIFY, OP_CHECKSIG))))
        assertEquals(tx.txOut[1].publicKeyScript, ByteVector(Script.write(listOf(OP_HASH160, OP_PUSHDATA(ByteVector("3545e6e33b832c47050f24d3eeb93c9c03948bc7")), OP_EQUAL))))
        assertEquals(hex, Hex.encode(Transaction.write(tx)))
    }

    @Test
    fun `decode transactions`() {
        // data copied from https://people.xiph.org/~greg/signdemo.txt
        val tx = Transaction.read("01000000010c432f4fb3e871a8bda638350b3d5c698cf431db8d6031b53e3fb5159e59d4a90000000000ffffffff0100f2052a010000001976a9143744841e13b90b4aca16fe793a7f88da3a23cc7188ac00000000")
        val script = Script.parse(tx.txOut[0].publicKeyScript)
        val publicKeyHash = when {
            script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] is OP_PUSHDATA && script[3] == OP_EQUALVERIFY && script[4] == OP_CHECKSIG -> (script[2] as OP_PUSHDATA).data
            else -> {
                throw RuntimeException("unexpected script $script")
            }
        }
        assertEquals("mkZBYBiq6DNoQEKakpMJegyDbw2YiNQnHT", Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, publicKeyHash))
    }

    @Test
    fun `create and verify simple transactions`() {
        val address = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"
        val (prefix, pubkeyHash) = Base58Check.decode(address)
        assertEquals(prefix, Base58.Prefix.PubkeyAddressTestnet)
        val amount = 1000L.toSatoshi()

        val privateKey = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet).first
        val publicKey = privateKey.publicKey()

        val previousTx = Transaction.read(
            "0100000001b021a77dcaad3a2da6f1611d2403e1298a902af8567c25d6e65073f6b52ef12d000000006a473044022056156e9f0ad7506621bc1eb963f5133d06d7259e27b13fcb2803f39c7787a81c022056325330585e4be39bcf63af8090a2deff265bc29a3fb9b4bf7a31426d9798150121022dfb538041f111bb16402aa83bd6a3771fa8aa0e5e9b0b549674857fafaf4fe0ffffffff0210270000000000001976a91415c23e7f4f919e9ff554ec585cb2a67df952397488ac3c9d1000000000001976a9148982824e057ccc8d4591982df71aa9220236a63888ac00000000"
        )

        // create a transaction where the sig script is the pubkey script of the tx we want to redeem
        // the pubkey script is just a wrapper around the pub key hash
        // what it means is that we will sign a block of data that contains txid + from + to + amount

        // step  #1: creation a new transaction that reuses the previous transaction's output pubkey script
        val tx1 = Transaction(
            version = 1L,
            txIn = listOf(
                TxIn(OutPoint(previousTx.hash, 0), signatureScript = listOf(), sequence = 0xFFFFFFFFL)
            ),
            txOut = listOf(
                TxOut(amount = amount, publicKeyScript = listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(pubkeyHash), OP_EQUALVERIFY, OP_CHECKSIG))
            ),
            lockTime = 0L
        )

        // step #2: sign the tx
        val sig = Transaction.signInput(tx1, 0, previousTx.txOut[0].publicKeyScript, SigHash.SIGHASH_ALL, privateKey)
        val tx2 = tx1.updateSigScript(0, listOf(OP_PUSHDATA(sig), OP_PUSHDATA(publicKey)))

        // redeem the tx
        Transaction.correctlySpends(tx2, listOf(previousTx), ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `create and sign p2sh transactions`() {
        val key1 = PrivateKey.fromHex("C0B91A94A26DC9BE07374C2280E43B1DE54BE568B2509EF3CE1ADE5C9CF9E8AA01")
        val pub1 = key1.publicKey()
        val key2 = PrivateKey.fromHex("5C3D081615591ABCE914D231BA009D8AE0174759E4A9AE821D97E28F122E2F8C01")
        val pub2 = key2.publicKey()
        val key3 = PrivateKey.fromHex("29322B8277C344606BA1830D223D5ED09B9E1385ED26BE4AD14075F054283D8C01")
        val pub3 = key3.publicKey()

        // we want to spend the first output of this tx
        val previousTx = Transaction.read(
            "01000000014100d6a4d20ff14dfffd772aa3610881d66332ed160fc1094a338490513b0cf800000000fc0047304402201182201b586c6bfe6fd0346382900834149674d3cbb4081c304965440b1c0af20220023b62a997f4385e9279dc1078590556c6c6a85c3ec20fda407e95eb270e4de90147304402200c75f91f8bd741a8e71d11ff6a3e931838e32ceead34ccccfe3f73f01a81e45f02201795881473644b5f5ee6a8d8a90fe16e60eacace40e88900c375af2e0c51e26d014c69522103bd95bfc136869e2e5e3b0491e45c32634b0201a03903e210b01be248e04df8702103e04f714a4010ca5bb1423ef97012cb1008fb0dfd2f02acbcd3650771c46e4a8f2102913bd21425454688bdc2df2f0e518c5f3109b1c1be56e6e783a41c394c95dc0953aeffffffff0140420f00000000001976a914298e5c1e2d2cf22deffd2885394376c7712f9c6088ac00000000"
        )
        val privateKey = PrivateKey.fromBase58("92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM", Base58.Prefix.SecretKeyTestnet).first
        val publicKey = privateKey.publicKey()

        // create and serialize a "2 out of 3" multisig script
        val redeemScript = Script.write(Script.createMultiSigMofN(2, listOf(pub1, pub2, pub3)))

        // the multisig adress is just that hash of this script
        val multisigAddress = Crypto.hash160(redeemScript)

        // we want to send money to our multisig adress by redeeming the first output
        // of 41e573704b8fba07c261a31c89ca10c3cb202c7e4063f185c997a8a87cf21dea
        // using our private key 92TgRLMLLdwJjT1JrrmTTWEpZ8uG7zpHEgSVPTbwfAs27RpdeWM

        // create a tx with empty input signature scripts
        val tx = Transaction(
            version = 1L,
            txIn = listOf(
                TxIn(OutPoint(previousTx.hash, 0), signatureScript = listOf(), sequence = 0xFFFFFFFFL)
            ),
            txOut = listOf(
                TxOut(
                    amount = 900000L.toSatoshi(), // 0.009 BTC in satoshi, meaning the fee will be 0.01-0.009 = 0.001
                    publicKeyScript = listOf(OP_HASH160, OP_PUSHDATA(multisigAddress), OP_EQUAL)
                )
            ),
            lockTime = 0L
        )

        // and sign it
        val sig = Transaction.signInput(tx, 0, previousTx.txOut[0].publicKeyScript, SigHash.SIGHASH_ALL, privateKey)
        val signedTx = tx.updateSigScript(0, listOf(OP_PUSHDATA(sig), OP_PUSHDATA(privateKey.publicKey().toUncompressedBin())))
        Transaction.correctlySpends(signedTx, listOf(previousTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

        // how to spend our tx ? let's try to sent its output to our public key
        val spendingTx = Transaction(
            version = 1L,
            txIn = listOf(
                TxIn(OutPoint(signedTx.hash, 0), signatureScript = listOf(), sequence = 0xFFFFFFFFL)
            ),
            txOut = listOf(
                TxOut(
                    amount = 900000L.toSatoshi(),
                    publicKeyScript = listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(publicKey.hash160()), OP_EQUALVERIFY, OP_CHECKSIG)
                )
            ),
            lockTime = 0L
        )

        // we need at least 2 signatures
        val sig1 = Transaction.signInput(spendingTx, 0, redeemScript, SigHash.SIGHASH_ALL, key1)
        val sig2 = Transaction.signInput(spendingTx, 0, redeemScript, SigHash.SIGHASH_ALL, key2)

        // update our tx with the correct sig script
        val sigScript = listOf(OP_0, OP_PUSHDATA(sig1), OP_PUSHDATA(sig2), OP_PUSHDATA(redeemScript))
        val signedSpendingTx = spendingTx.updateSigScript(0, sigScript)
        Transaction.correctlySpends(signedSpendingTx, listOf(signedTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `create and sign pay2pk transactions with multiple inputs and outputs`() {
        val destAddress = "moKHwpsxovDtfBJyoXpof21vvWooBExutV"
        val destAmount = 3000000.sat()
        val changeAddress = "mvHPesWqLXXy7hntNa7vbAoVwqN5PnrwJd"
        val changeAmount = 1700000.sat()
        val previousTx = listOf(
            Transaction.read("0100000001bb4f5a244b29dc733c56f80c0fed7dd395367d9d3b416c01767c5123ef124f82000000006b4830450221009e6ed264343e43dfee2373b925915f7a4468e0bc68216606e40064561e6c097a022030f2a50546a908579d0fab539d5726a1f83cfd48d29b89ab078d649a8e2131a0012103c80b6c289bf0421d010485cec5f02636d18fb4ed0f33bfa6412e20918ebd7a34ffffffff0200093d00000000001976a9145dbf52b8d7af4fb5f9b75b808f0a8284493531b388acf0b0b805000000001976a914807c74c89592e8a260f04b5a3bc63e7bef8c282588ac00000000"),
            Transaction.read("0100000001345b2a5f872f73de2c4f32e4c28834832ba4c2ce5e54af1e8b897f49766141af00000000fdfe0000483045022100e5a3c850d7cb8776bfbd3fa4b24ce9bb3514fe96a922449dd14c03f5fa04d6ad022035710c6b9c2922c7b8de02fb674cb61e2c18ea439b190b4f55c14fad1ed89eb801483045022100ec6b1ea37cc5694312f7d5fe72280ef21688d11e00f307fdcc1eff30718e30560220542e02c32e3e392cce7adfc287c72f7f1e51ca73980505c2bebcf0b7b441ff90014c6952210394d30868076ab1ea7736ed3bdbec99497a6ad30b25afd709cdf3804cd389996a21032c58bc9615a6ff24e9132cef33f1ef373d97dc6da7933755bc8bb86dbee9f55c2102c4d72d99ca5ad12c17c9cfe043dc4e777075e8835af96f46d8e3ccd929fe192653aeffffffff0100350c00000000001976a914801d5eb10d2c1513ba1960fd8893f0ddbbe33bb388ac00000000")
        )
        val keys = listOf(
            PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet),
            PrivateKey.fromBase58("93NJN4mhL21FxRbfHZJ2Cou1YnrJmWNkujmZxeT7CPKauJkGv5g", Base58.Prefix.SecretKeyTestnet)
        ).map { it.first }

        // create a tx with empty input signature scripts
        val tx = Transaction(
            version = 1L,
            txIn = previousTx.map { tx -> TxIn(OutPoint(tx, 0), ByteVector.empty, 0xFFFFFFFFL) },
            txOut = listOf(
                TxOut(
                    amount = destAmount,
                    publicKeyScript = listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(Base58Check.decode(destAddress).second), OP_EQUALVERIFY, OP_CHECKSIG)
                ),
                TxOut(
                    amount = changeAmount,
                    publicKeyScript = listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(Base58Check.decode(changeAddress).second), OP_EQUALVERIFY, OP_CHECKSIG)
                )
            ),
            lockTime = 0L
        )

        // sign inputs
        val sig1 = Transaction.signInput(tx, 0, previousTx[0].txOut[0].publicKeyScript, SIGHASH_ALL, 0.sat(), SigVersion.SIGVERSION_BASE, keys[0])
        val sig2 = Transaction.signInput(tx, 1, previousTx[1].txOut[0].publicKeyScript, SIGHASH_ALL, 0.sat(), SigVersion.SIGVERSION_BASE, keys[1])
        val tx1 = tx
            .updateSigScript(0, listOf(OP_PUSHDATA(sig1), OP_PUSHDATA(keys[0].publicKey().value)))
            .updateSigScript(1, listOf(OP_PUSHDATA(sig2), OP_PUSHDATA(keys[1].publicKey().toUncompressedBin())))

        assertEquals(ByteVector32("882e971dbdb7b762cd07e5db016d3c81267ec5233186a31e6f40457a0a56a311"), tx1.txid)
        assertEquals(
            "01000000026c8a0bb4fef409509800066578a718e9a771082d94e96e0885a4b6a15b720c02000000006b483045022100e5510a2f15f03788ee2aeb2115edc96089596e3a0f0c1b1abfbbf069f4beedb802203faf6ec92a5a4ed2ce5fd42621be99746b57eca0eb46d322dc076080338b6c5a0121030533e1d2e9b7576fef26de1f34d67887158b7af1b040850aab6024b07925d70affffffffaf01f14881716b8acb062c33e7a66fc71e77bb2e4359b1f91b959aeb4f8837f1000000008b483045022100d3e5756f36e39a801c71c406124b3e0a66f0893a7fea46c69939b84715137c40022070a0e96e37c0a8e8c920e84fc63ed1914b4cef114a027f2d027d0a4a04b0b52d0141040081a4cce4c497d51d2f9be2d2109c00cbdef252185ca23074889604ace3504d73fd5f5aaac6423b04e776e467a948e1e79cb8793ded5f4b59c730c4460a0f86ffffffff02c0c62d00000000001976a914558c6b340f5abd22bf97b15cbc1483f8f1b54f5f88aca0f01900000000001976a914a1f93b5b00f9f5e8ade5549b58ed06cdc5c8203e88ac00000000",
            tx1.toString(),
        )

        // now check that we can redeem this tx
        Transaction.correctlySpends(tx1, previousTx, ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `sign a 3-to-2 transaction`() {
        val previousTx = listOf(
            Transaction.read("0100000001cec6dd9f7ddc640f7bb54daf5623040532b8783472df1de3adc70df9b0f04f05000000006b483045022100ea006269fdf8b7308107e9469e575af4eeb2dbf1bcb273416ba6da92106ad56302206affb99984a40334c7d8b991c285a5f89e47ff62879e69b28fafecf7bd70b00f012102a97bf098a7cfc5c81a113b76922ef24abfa27d6e9991db724f9090a8426c9d53ffffffff024084fe00000000001976a914a1c03c1932f6afd5eab9163f9140151cae17df3388ac40420f00000000001976a9148c9648cab53a1fb8861daff0f2378c7b9e81a3ab88ac00000000"),
            Transaction.read("0100000001cec6dd9f7ddc640f7bb54daf5623040532b8783472df1de3adc70df9b0f04f05010000006b483045022100d6fb138dca5e6cce925a4bcc322d02ab194f68a0c2794bb1a555dc1ff8c2465f02205a4977af8f398b013da33e61a35f83578c3a9cccea3328b6c982ff4dc8092c7e01210224fc92517bc13b1e9f609054afc2539f2f121f4c1e45fb46fac21364c42440c6ffffffff01400d0300000000001976a9146a3e65bf746bcd7af3493e19451451a8a4da331588ac00000000"),
            Transaction.read("01000000016d1f1a7f8c1307139ef78080ba8442852c6766d3fbb826d2ac0e6fb2f72dd8dc000000008b483045022100bdd23d0f98a4173a64fa432b8bf4ac41261a671f2c6c690d57ac839866d78bb202207bddb87ca95c9cef45de30a75144e5513571aa7938635b9e051b1c20f01088a60141044aec194c55c97f4519535f50f5539c6915045ecb79a36281dee6db55ffe1ad2e55f4a1c0e0950d3511e8f205b45cafa348a4a2ab2359246cb3c93f6532c4e8f5ffffffff0140548900000000001976a914c622640075eaeda95a5ac26fa05a0b894a3def8c88ac00000000")
        )
        val keys = listOf(
            PrivateKey.fromBase58("cW6bSKtH3oMPA18cXSMR8ASHztrmbwmCyqvvN8x3Tc7WG6TyrJDg", Base58.Prefix.SecretKeyTestnet),
            PrivateKey.fromBase58("93Ag8t83NW9WmPbhqLCSUNckARpbpgWtp4EWGidtj6h6pVQgGN4", Base58.Prefix.SecretKeyTestnet),
            PrivateKey.fromBase58("921vnTeSQCN7GMHdiHyaoZ1JSugTtzvg8rqyXH9HmFtBgrNDxCT", Base58.Prefix.SecretKeyTestnet)
        ).map { it.first }

        val dest1 = "n2Jrcf7cJH7wMJdhKZGVi2jaSnV2BwYE9m"
        // priv: 926iWgQDq5dN84BJ4q2fu4wjSSaVWFxwanE8EegzMh3vGCUBJ94
        val dest2 = "mk6kmMF5EEXksBkZxi7FniwwRgWuZuwDpo"
        // priv: 91r7coHBdzfgfm2p3ToJ3Bu6kcqL3BvSo5m4ENzMZzsimRKH8aq
        val amount1 = 3_000_000.sat() // 0.03 btc
        val amount2 = 7_000_000.sat() // 0.07 btc

        // create a tx with empty input signature scripts
        val tx = Transaction(
            version = 1L,
            txIn = listOf(
                TxIn(OutPoint(previousTx[0], 1), ByteVector.empty, 0xffffffffL),
                TxIn(OutPoint(previousTx[1], 0), ByteVector.empty, 0xffffffffL),
                TxIn(OutPoint(previousTx[2], 0), ByteVector.empty, 0xffffffffL)
            ),
            txOut = listOf(
                TxOut(
                    amount = amount1,
                    publicKeyScript = listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(Base58Check.decode(dest1).second), OP_EQUALVERIFY, OP_CHECKSIG),
                ),
                TxOut(
                    amount = amount2,
                    publicKeyScript = listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(Base58Check.decode(dest2).second), OP_EQUALVERIFY, OP_CHECKSIG)
                )
            ),
            lockTime = 0L
        )

        val sig1 = Transaction.signInput(tx, 0, previousTx[0].txOut[1].publicKeyScript, SIGHASH_ALL, 0.sat(), SigVersion.SIGVERSION_BASE, keys[0])
        val sig2 = Transaction.signInput(tx, 1, previousTx[1].txOut[0].publicKeyScript, SIGHASH_ALL, 0.sat(), SigVersion.SIGVERSION_BASE, keys[1])
        val sig3 = Transaction.signInput(tx, 2, previousTx[2].txOut[0].publicKeyScript, SIGHASH_ALL, 0.sat(), SigVersion.SIGVERSION_BASE, keys[2])
        val signedTx = tx
            .updateSigScript(0, listOf(OP_PUSHDATA(sig1), OP_PUSHDATA(keys[0].publicKey().value)))
            .updateSigScript(1, listOf(OP_PUSHDATA(sig2), OP_PUSHDATA(keys[1].publicKey().toUncompressedBin())))
            .updateSigScript(2, listOf(OP_PUSHDATA(sig3), OP_PUSHDATA(keys[2].publicKey().toUncompressedBin())))

        assertEquals(signedTx.txid, ByteVector32("e8570dd062de8e354b18f6308ff739a51f25db75563c4ee2bc5849281263528f"))
        assertEquals(
            "0100000003864d5e5ec82c9e6f4ac52b8fa47b77f8616bbc26fcf668432c097c5add169584010000006a47304402203be0cff1faacadce3b02d615a8ac15532f9a90bd30e109eaa3e01bfa3a97d90b0220355f3bc382e35b9cae24e5d674f200b289bb948675ce1b5c931029ccb23ae836012102fd18c2a069488288ae93c2157dff3fd657a39426e8753512a5547f046b4a2cbbffffffffd587b10688e6d56225dd4dc488b74229a353e4613cbe1deadaef52b56616baa9000000008b483045022100ab98145e8526b32e821beeaed41a98da68c3c75ee13c477ee0e3d66a626217e902204d015af2e7dba834bbe421dd0b1353a1060dafee58c284dd763e07639858f9340141043ca81d9fe7996372eb21b2588af07c7fbdb6d4fc1da13aaf953c520ba1da4f87d53dfcba3525369fdb248e60233fdf6df0a8183a6dd5699c9a6f5c537367c627ffffffff94a162b4aab080a09fa982a5d7f586045ba2a4c653c98ff47b952d43c25b45fd000000008a47304402200e0c0223d169282a48731b58ff0673c00205deb3f3f4f28d99b50730ada1571402202fa9f051762d8e0199791ea135df1f393578c1eea530bec00fa16f6bba7e3aa3014104626f9b06c44bcfd5d2f6bdeab456591287e2d2b2e299815edf0c9fd0f23c21364ed5dbe97c9c6e2be40fff40c31f8561a9dee015146fe59ecf68b8a377292c72ffffffff02c0c62d00000000001976a914e410e8bc694e8a39c32a273eb1d71930f63648fe88acc0cf6a00000000001976a914324505870d6f21dca7d2f90642cd9603553f6fa688ac00000000",
            signedTx.toString()
        )

        // now check that we can redeem this tx
        Transaction.correctlySpends(signedTx, previousTx, ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `compute tx weight`() {
        val tx = Transaction.read(
            "02000000000101d5babb96fc16d69455555edad0147525dba4581a4698fa5ffa270038663622d00100000000ffffffff04f6540000000000002200205751128e230201252054ab0fe8bfb897bcea7558dcb3cb43b435f11eea307b96f6540000000000001976a91470c0b535309db2aff3feabf5a54ad54ed28860e888acf65400000000000022002014aa3f91b837d2e3907a369b154368bc3a56cb6d2e7ca9f8163bfab480683ccef6540000000000002200206b39ae68b56cf3a1abb4be38fb55aaa6f5607f200642f52941b07c32572e49070400483045022100bb9d60b3d659329d346611fc107cf6aff5d29fb41209f55469978c1766f4571c02205a7466982e4ededb6adaccb44c8e68839b3bb9a7a042d6b3f1fef608cf8ab00601483045022100fe2c561731015d5d20083d57ec6d1b640359191dc239b8867ac064b930c3795d02201f54e0025ea1f074abb9c7d9eaed791d11f8fbd1387235a56e6500d6130e9b66014752210313151c5c6bb22d2d989cba0f12a51545d6179bae0ede36dcea598e06b0a279db2103c28b94b58f539ea687a941f8256c14b9b856d00a33bd526851ab021b69c87b6552ae00000000"
        )
        assertEquals(tx.weight(), 1078)
    }

    @Test
    fun `compute toString (segwit tx)`() {
        val hex =
            "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
        val tx = Transaction.read(hex)
        assertEquals(hex, tx.toString())
    }

}
