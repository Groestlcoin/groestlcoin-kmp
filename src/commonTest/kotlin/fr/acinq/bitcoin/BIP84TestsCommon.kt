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

import fr.acinq.bitcoin.Bitcoin.computeBIP84Address
import kotlin.test.Test
import kotlin.test.assertEquals

class BIP84TestsCommon {
    /**
     * BIP 84 (Derivation scheme for P2WPKH based accounts) reference tests
     * see https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
     */
    @Test
    fun `BIP49 reference tests`() {
        val seed = MnemonicCode.toSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(" "), "")
        val master = DeterministicWallet.generate(seed)
        assertEquals(DeterministicWallet.encode(master, DeterministicWallet.zprv), "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBZRTRVy")
        assertEquals(DeterministicWallet.encode(DeterministicWallet.publicKey(master), DeterministicWallet.zpub), "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzx6o5Ln")

        val accountKey = DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/17'/0'"))
        assertEquals(DeterministicWallet.encode(accountKey, DeterministicWallet.zprv), "zprvAceMCrxbVvUavGGXAKTeDaNBZCkDAxU2AYyRB6zMxxPNkTSHX5o3tum6aqqZwqktzPpM5gwPmfUgq7jGRZmNSgRgJWLFiGqhkdNHdEoMRNS")
        assertEquals(DeterministicWallet.encode(DeterministicWallet.publicKey(accountKey), DeterministicWallet.zpub), "zpub6qdhcNVVLJ2t8kLzGLzeaiJv7EahaRBsXmu1yVPyXHvMdFmS4d7JSi5aS6mc1oz5k6DZN781Ffn3GAs3r2FJnCPSw5nti63s3c9EDg2u7MS")

        val key = DeterministicWallet.derivePrivateKey(accountKey, listOf(0L, 0L))
        assertEquals(key.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/17'/0'/0/0")).secretkeybytes)
        assertEquals(key.privateKey.toBase58(Base58.Prefix.SecretKey), "L4mSsRa7DVFMez7MxcL9cV5ZxeKdMJpJmqJtdcGDz9oJM6sQsNz2")
        assertEquals(
            key.publicKey,
            PublicKey.fromHex("02b61ee53e24da178693ef0e7bdf34a250094deb2ec9dbd80b080d7242e54df383")
        )
        assertEquals(computeBIP84Address(key.publicKey, Block.LivenetGenesisBlock.hash), "grs1qrm2uggqj846nljryvmuga56vtwfey0dtnc4z55")

        val key1 = DeterministicWallet.derivePrivateKey(accountKey, listOf(0L, 1L))
        assertEquals(key1.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/17'/0'/0/1")).secretkeybytes)
        assertEquals(key1.privateKey.toBase58(Base58.Prefix.SecretKey), "KygxBG82bZ2SrkhaFMLRYPUMLiGmjBANxg7vDCBNVqFhmveTZKWr")
        assertEquals(
            key1.publicKey,
            PublicKey.fromHex("028d25e8e74ddab20f6769f24ef09bf54fa0502b0ab566789da7cd2a565f199c9a")
        )
        assertEquals(computeBIP84Address(key1.publicKey, Block.LivenetGenesisBlock.hash), "grs1qy2vlj0w9kp408mg74trj9s08azhzschw5ayp2g")

        val key2 = DeterministicWallet.derivePrivateKey(accountKey, listOf(1L, 0L))
        assertEquals(key2.secretkeybytes, DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/17'/0'/1/0")).secretkeybytes)
        assertEquals(key2.privateKey.toBase58(Base58.Prefix.SecretKey), "L3UPrg3xRSrVm3iHEEVLsyuXK54XJSJ9yZBzyEtrB1HNzAwnarPr")
        assertEquals(
            key2.publicKey,
            PublicKey.fromHex("02af1f15ed1969b0de88bb7858b6f0e3a12440f80534e21ee2422c81d644728650")
        )
        assertEquals(computeBIP84Address(key2.publicKey, Block.LivenetGenesisBlock.hash), "grs1q4v3e7r759yegjtcwrevg5spe5vfvwkhhwz2zca")
    }
}