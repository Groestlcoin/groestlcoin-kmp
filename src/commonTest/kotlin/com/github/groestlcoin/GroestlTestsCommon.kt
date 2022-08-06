/*
 * Copyright 2022 Groestlcoin Developers
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

package com.github.groestlcoin

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertEquals

class GroestlTestsCommon {
    @Test
    fun hash() {
        val input = Hex.decode("700000000000000000000000000000000000000000000000000000000000000000000000bb2866aaca46c4428ad08b57bc9d1493abaf64724b6c3052a7c8f958df68e93c29ab5f49ffff001d1dac2b7c")
        val expectedHash = "f7283464f9c381f54154a0eb19e66dc44850d3cad22bf1798fbd3e450ccdddf1"
        val actualHashTwo = Hex.encode(Groestl().hash(input))
        assertEquals(expectedHash, actualHashTwo)

        val groestl = Groestl();
        groestl.update(input, 0, input.size)
        val actualHashThree = ByteArray(32)
        groestl.doFinal(actualHashThree, 0)
        assertEquals(expectedHash, Hex.encode(actualHashThree))
    }
}