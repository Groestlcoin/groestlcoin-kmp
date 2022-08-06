/*
 * Copyright 2020 Groestlcoin Developers
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

import com.appmattus.crypto.Algorithm
import fr.acinq.bitcoin.crypto.Digest


public class Groestl : Digest {
    private val digestGroestl = Algorithm.Groestl512.createDigest()

    override fun reset() {
        digestGroestl.reset()
    }

    override fun getAlgorithmName(): String {
        return "groestl-2x"
    }

    public override fun update(input: ByteArray, inputOffset: Int, len: Int) {
        digestGroestl.update(input, inputOffset, len)
    }

    override fun update(input: Byte) {
        digestGroestl.update(input)
    }

    override fun getDigestSize(): Int {
        return 32
    }

    override fun doFinal(out: ByteArray, outOffset: Int): Int {
        val hash512 = digestGroestl.digest()
        digestGroestl.reset()
        digestGroestl.update(hash512)
        digestGroestl.digest(out, outOffset, getDigestSize())
        return out.size
    }
}

