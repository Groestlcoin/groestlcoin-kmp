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

package fr.acinq.bitcoin.reference

import fr.acinq.bitcoin.Transaction
import fr.acinq.secp256k1.Hex
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.kodein.memory.file.openReadableFile
import org.kodein.memory.file.resolve
import org.kodein.memory.text.readString
import org.kodein.memory.use
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertEquals

class SigHashTestsCommon {

    @Test @Ignore
    fun `reference client sighash test`() {
        val file = TransactionTestsCommon.resourcesDir().resolve("data/sighash.json")
        val raw = file.openReadableFile().use { it.readString() }
        val format = Json { ignoreUnknownKeys = true }
        val json = format.parseToJsonElement(raw)
        // 	["raw_transaction, script, input_index, hashType, signature_hash (result)"],
        json.jsonArray.filter { it.jsonArray.size == 5 }.map { it.jsonArray }.forEach {
            val rawTx = it[0].jsonPrimitive.content
            val script = it[1].jsonPrimitive.content
            val inputIndex = it[2].jsonPrimitive.int
            val hashType = it[3].jsonPrimitive.int
            val signatureHash = it[4].jsonPrimitive.content
            val tx = Transaction.read(rawTx)
            val hash = Transaction.hashForSigning(tx, inputIndex, Hex.decode(script), hashType)
            assertEquals(signatureHash, Hex.encode(hash.reversed().toByteArray()))
        }
    }

}
