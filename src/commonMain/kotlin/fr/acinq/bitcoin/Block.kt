package fr.acinq.bitcoin

import fr.acinq.bitcoin.crypto.Crypto
import fr.acinq.bitcoin.OP_CHECKSIG
import fr.acinq.bitcoin.OP_PUSHDATA
import kotlinx.io.InputStream
import kotlinx.io.OutputStream
import kotlinx.serialization.InternalSerializationApi

/**
 *
 * @param version           Block version information, based upon the software version creating this block
 * @param hashPreviousBlock The hash value of the previous block this particular block references. Please not that
 *                          this hash is not reversed (as opposed to Block.hash)
 * @param hashMerkleRoot    The reference to a Merkle tree collection which is a hash of all transactions related to this block
 * @param time              A timestamp recording when this block was created (Will overflow in 2106[2])
 * @param bits              The calculated difficulty target being used for this block
 * @param nonce             The nonce used to generate this block… to allow variations of the header and compute different hashes
 */
@ExperimentalStdlibApi
@InternalSerializationApi
data class BlockHeader(val version: Long, val hashPreviousBlock: ByteVector32, val hashMerkleRoot: ByteVector32, val time: Long, val bits: Long, val nonce: Long) {
    val hash: ByteVector32 by lazy { ByteVector32(Crypto.hash256(BlockHeader.write(this))) }

    val blockId: ByteVector32 by lazy { hash.reversed() }

    @ExperimentalStdlibApi
    @InternalSerializationApi
    @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
    companion object : BtcSerializer<BlockHeader> {
        override fun read(input: InputStream, protocolVersion: Long): BlockHeader {
            val version = BtcSerializer.uint32(input)
            val hashPreviousBlock = BtcSerializer.hash(input)
            val hashMerkleRoot = BtcSerializer.hash(input)
            val time = BtcSerializer.uint32(input)
            val bits = BtcSerializer.uint32(input)
            val nonce = BtcSerializer.uint32(input)
            return BlockHeader(version, hashPreviousBlock.byteVector32(), hashMerkleRoot.byteVector32(), time, bits, nonce)
        }

        override fun write(message: BlockHeader, output: OutputStream, protocolVersion: Long) {
            BtcSerializer.writeUInt32(message.version, output)
            BtcSerializer.writeBytes(message.hashPreviousBlock, output)
            BtcSerializer.writeBytes(message.hashMerkleRoot, output)
            BtcSerializer.writeUInt32(message.time, output)
            BtcSerializer.writeUInt32(message.bits, output)
            BtcSerializer.writeUInt32(message.nonce, output)
        }

        fun getDifficulty(header: BlockHeader): Any = `???`()

        /**
         *
         * @param bits difficulty target
         * @return the amount of work represented by this difficulty target, as displayed
         *         by bitcoin core
         */
        fun blockProof(bits: Long): Double = `???`()

        fun blockProof(header: BlockHeader): Double = blockProof(header.bits)

        /**
         * Proof of work: hash(header) <= target difficulty
         *
         * @param header block header
         * @return true if the input block header validates its expected proof of work
         */
        fun checkProofOfWork(header: BlockHeader): Boolean = `???`()

        fun calculateNextWorkRequired(lastHeader: BlockHeader, lastRetargetTime: Long): Long = `???`()
    }
}

/**
 * see https://en.bitcoin.it/wiki/Protocol_specification#Merkle_Trees
 */
object MerkleTree {
    tailrec fun computeRoot(tree: List<ByteVector32>): ByteVector32 {
        return when {
            tree.size == 1 -> tree[0]
            (tree.size % 2) != 0 -> computeRoot(tree + listOf(tree.last())) // append last element again
            else -> {
                val tree1 = mutableListOf<ByteVector32>()
                for (i in 0 until (tree.size / 2)) {
                    val hash = Crypto.hash256(tree[2 * i].toByteArray() + tree[2 * i + 1].toByteArray())
                    tree1.add(hash.byteVector32())
                }
                computeRoot(tree1.toList())
            }
        }
    }
}

@InternalSerializationApi
@ExperimentalStdlibApi
data class Block(val header: BlockHeader, val tx: List<Transaction>) {
    val hash: ByteVector32 by lazy { header.hash }
    val blockId: ByteVector32 by lazy { hash.reversed() }

    @InternalSerializationApi
    @ExperimentalStdlibApi
    companion object : BtcSerializer<Block> {
        override fun write(message: Block, out: OutputStream, protocolVersion: Long) {
            BlockHeader.write(message.header, out)
            BtcSerializer.writeCollection(message.tx, out, Transaction, protocolVersion)

        }

        override fun read(input: InputStream, protocolVersion: Long): Block {
            val raw = BtcSerializer.bytes(input, 80)
            val header = BlockHeader.read(raw)
            return Block(header, BtcSerializer.readCollection(input, Transaction, protocolVersion))
        }

        override fun validate(message: Block) {
            BlockHeader.validate(message.header)
            require(message.header.hashMerkleRoot == MerkleTree.computeRoot(message.tx.map { it -> it.hash })) { "invalid block:  merkle root mismatch" }
            require(message.tx.map { it.hash }.toSet().size == message.tx.size) { "invalid block: duplicate transactions" }
            message.tx.map { Transaction.validate(it) }
        }

        /**
         * Proof of work: hash(block) <= target difficulty
         *
         * @param block
         * @return true if the input block validates its expected proof of work
         */
        fun checkProofOfWork(block: Block): Boolean = `???`()

        // genesis blocks
        val LivenetGenesisBlock = {
            val script = listOf(
                OP_PUSHDATA(BtcSerializer.writeUInt32(486604799L)),
                OP_PUSHDATA(ByteVector("04")),
                OP_PUSHDATA("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks".encodeToByteArray())
            )
            val scriptPubKey = listOf(
                OP_PUSHDATA(ByteVector("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")),
                OP_CHECKSIG
            )
            Block(
                BlockHeader(version = 1, hashPreviousBlock = ByteVector32.Zeroes, hashMerkleRoot = ByteVector32("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"), time = 1231006505, bits = 0x1d00ffff, nonce = 2083236893),
                listOf(
                    Transaction(version = 1,
                        txIn = listOf(TxIn.coinbase(script)),
                        txOut = listOf(TxOut(amount = Satoshi(5000000000), publicKeyScript = scriptPubKey)),
                        lockTime = 0)
                )
            )
        }.invoke()

        val TestnetGenesisBlock = LivenetGenesisBlock.copy(header = LivenetGenesisBlock.header.copy(time = 1296688602, nonce = 414098458))

        val RegtestGenesisBlock = LivenetGenesisBlock.copy(header = LivenetGenesisBlock.header.copy(bits = 0x207fffffL, nonce = 2, time = 1296688602))

        val SegnetGenesisBlock = LivenetGenesisBlock.copy(header = LivenetGenesisBlock.header.copy(bits = 503447551, time = 1452831101, nonce = 0))

    }
}