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

import fr.acinq.bitcoin.reference.TransactionTestsCommon
import fr.acinq.secp256k1.Hex
import org.kodein.memory.file.openReadableFile
import org.kodein.memory.file.resolve
import org.kodein.memory.use
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BlockTestsCommon {
    private val blockData = run {
        val file = TransactionTestsCommon.resourcesDir().resolve("block1.dat")
        file.openReadableFile().use {
            val len = it.available
            // workaround for a bug in kotlin memory file where dstOffset cannot be 0 but is still ignored...
            val buffer = ByteArray(len)
            for (i in buffer.indices) buffer[i] = it.readByte()
            buffer
        }
    }

    @Test @Ignore
    fun `read blocks`() {
        val block = Block.read(blockData)
        assertTrue(Block.checkProofOfWork(block))

        assertEquals(MerkleTree.computeRoot(block.tx.map { it.hash }), block.header.hashMerkleRoot)

        // check that we can deserialize and re-serialize scripts
        for (tx in block.tx) {
            for (txin in tx.txIn) {
                if (!OutPoint.isCoinbase(txin.outPoint)) {
                    val script = Script.parse(txin.signatureScript)
                    assertEquals(txin.signatureScript, Script.write(script).byteVector())
                }
            }
            for (txout in tx.txOut) {
                val script = Script.parse(txout.publicKeyScript)
                assertEquals(txout.publicKeyScript, Script.write(script).byteVector())
            }
        }
    }

    @Test
    fun `serialize and deserialize blocks`() {
        val block = Block.read(blockData)
        val check = Block.write(block)
        assertEquals(check.byteVector(), blockData.byteVector())
    }

    @Test
    fun `compute proof of work`() {
        assertEquals(
            UInt256(Hex.decode("0000000000000000000000000000000000000000000000000000000400040004")),
            BlockHeader.blockProof(473956288)
        )
        assertEquals(
            UInt256(Hex.decode("0000000000000000000000000000000000000000000000000000010fc306ae30")),
            BlockHeader.blockProof(469823783)
        )
        assertEquals(
            UInt256(Hex.decode("000000000000000000000000000000000000000000000000000003177fdc0ed1")),
            BlockHeader.blockProof(458411200)
        )
        assertEquals(
            UInt256(Hex.decode("0000000000000000000000000000000000000000000000000000000672b107dd")),
            BlockHeader.blockProof(472363968)
        )
    }

    @Test
    fun `check proof of work`() {
        val headers = sequenceOf(
            "700000005ddb702e6d4a2d711a761557fc2aac3297de060f5a072ccbd17b380400000000c9732011e1eecfe190d3a1c705ad37b26a8c238fd0eb2a33c301fb844e9d1226cb717b53b6ba021c9d00a302",
            "03000000b33a09b2c75526aaed7dffe9b7d49c3f40ed9209610a69c1a956e5050000000049894605c4e22826c90e6cf99466d97368471a547908e7073d3124ac0da97d49098ade568a001a1cb3fa1708",
            "00000020465b0c116ee84b6e722ff16ab8c9252bf541f2f78d2caadef1080000000000006cf5bccc88c2a52abcad9389aacddc8c0195e6010ec6042ec6a36b1b0bf9c5135f58656077b00e1ae0da285f",
            "00000020465b0c116ee84b6e722ff16ab8c9252bf541f2f78d2caadef1080000000000006cf5bccc88c2a52abcad9389aacddc8c0195e6010ec6042ec6a36b1b0bf9c5135f58656077b00e1ae0da285f"
        ).map { BlockHeader.read(it) }

        headers.forEach { assertTrue(BlockHeader.checkProofOfWork(it)) }
    }

    @Test
    fun `calculate next work required`() {
        val header = BlockHeader(
            version = 2,
            hashPreviousBlock = ByteVector32.Zeroes,
            hashMerkleRoot = ByteVector32.Zeroes,
            time = 0L,
            bits = 0L,
            nonce = 0L
        )

        assertEquals(BlockHeader.calculateNextWorkRequired(header.copy(time = 1262152739, bits = 0x1d00ffff), 1261130161), 0x1d00d86aL)
        assertEquals(BlockHeader.calculateNextWorkRequired(header.copy(time = 1233061996, bits = 0x1d00ffff), 1231006505), 0x1d00ffffL)
        assertEquals(BlockHeader.calculateNextWorkRequired(header.copy(time = 1279297671, bits = 0x1c05a3f4), 1279008237), 0x1c0168fdL)
    }
}