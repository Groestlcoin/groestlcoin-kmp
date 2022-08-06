package fr.acinq.bitcoin

import fr.acinq.bitcoin.Bitcoin.computeBIP44Address
import fr.acinq.bitcoin.Bitcoin.computeBIP49Address
import fr.acinq.bitcoin.Bitcoin.computeBIP84Address
import kotlin.test.Test
import kotlin.test.assertEquals

class DeriveWalletKeysTestsCommon {
    private val mnemonics = "gun please vital unable phone catalog explain raise erosion zoo truly exist"
    private val seed = MnemonicCode.toSeed(mnemonics, "")
    private val master = DeterministicWallet.generate(seed)

    @Test
    fun `restore BIP44 wallet`() {
        val account = DeterministicWallet.derivePrivateKey(master, KeyPath("m/44'/1'/0'"))
        // some wallets will use tpub instead of upub
        val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(account), DeterministicWallet.tpub)
        assertEquals(xpub, "tpubDDamug2qVwe94yFJ38MM3ek2LiWiyjMmkQPhYMnHNZz5XHj7bj8xc7pFmyiYnCfqrSy62e1196qcpmKYhcUMcBTGMW4mEWf1v9H8wNY7A1v")
        assertEquals(
            deriveAddresses(xpub, DerivationScheme.BIP44),
            listOf("mmpDgTP9FQbJCcdkkuXLbjbvqg3j6xczBb", "mtXgQHM7Eawr6rjDWh7CrFtBQnbiZQEeZ2", "mw39H2JNixLuXLfTXqZr53M1n18en3ceoC", "mnK3W3DMnkKMPT3Kbx6gvrmWxch67gLB4x", "mpotVZLVr3fgbuBD2jzmwxVg7iAToPctnP")
        )
    }

    @Test
    fun `restore BIP49 wallet`() {
        val account = DeterministicWallet.derivePrivateKey(master, KeyPath("m/49'/1'/0'"))
        // some wallets will use tpub instead of upub
        val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(account), DeterministicWallet.upub)
        assertEquals(xpub, "upub5DKk7kdrLoL3HqrfVdf3mLZJ59g6Bix8UtB6YJQNSKfE3E6YU2Vq7dH7E8ce87jUAac4nRag6Zd7c2cXs45Q4nJcLdrJyNWPxS5D9J2L4L3")
        assertEquals(
            deriveAddresses(xpub, DerivationScheme.BIP49),
            listOf(
                "2NAV38YdZBS6s6b89QdmyPnjBxn6JiJDVSL",
                "2Mzxym6Rey5Mwnnxh6L134MaHFwTPNCcu1Z",
                "2N8tTGMc57REfePZzPkWqEGaYKHsraR5sEn",
                "2Mxfuivcx4TdGroh6Q2GmCR5rQB46id5bTF",
                "2N7uWEqMPCjzHynqSDaAnydZD6WfEtwDumP"
            )
        )
    }

    @Test
    fun `restore BIP84 wallet`() {
        val account = DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/1'/0'"))
        // some wallets will use tpub instead of upub
        val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(account), DeterministicWallet.vpub)
        assertEquals(xpub, "vpub5YmxxDXhaEfLoqxn8xJExGMSQepxRbJDFqyc9FpDKyW8z966eDsgqbTHnJCvc698MhN3FDRt49DuPBgdRufopecaeyffJCUKXRKHoKfcKeH")
        assertEquals(
            deriveAddresses(xpub, DerivationScheme.BIP84),
            listOf(
                "tgrs1ql63el50rtln6n4kxa76jrhuts3kxmk9wt87vsh",
                "tgrs1qa2hyhca4y07xqcl9r9m63rtv4hgdh063h6fgtm",
                "tgrs1q0lywyl3cdkuw29yuh6w0frqh4hnxdj0m4u6ugc",
                "tgrs1q4dg72vn06mrjh3yyzpkws3w2z0whrys8g0e75x",
                "tgrs1qx4g3glhflr42clkkla9ty0vmfcmme9a42llcfj"
            )
        )
    }

    companion object {
        sealed class DerivationScheme {
            object BIP44 : DerivationScheme()
            object BIP49 : DerivationScheme()
            object BIP84 : DerivationScheme()
        }

        fun deriveAddresses(xpub: String, derivationScheme: DerivationScheme): List<String> {
            val (prefix, master) = DeterministicWallet.ExtendedPublicKey.decode(xpub)
            return (0L..4L).map {
                val pub = DeterministicWallet.derivePublicKey(master, listOf(0L, it))
                val address = when {
                    prefix == DeterministicWallet.tpub && derivationScheme == DerivationScheme.BIP44 -> computeBIP44Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
                    prefix == DeterministicWallet.tpub && derivationScheme == DerivationScheme.BIP49 -> computeBIP49Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
                    prefix == DeterministicWallet.upub && derivationScheme == DerivationScheme.BIP49 -> computeBIP49Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
                    prefix == DeterministicWallet.vpub && derivationScheme == DerivationScheme.BIP84 -> computeBIP84Address(pub.publicKey, Block.TestnetGenesisBlock.hash)
                    prefix == DeterministicWallet.xpub && derivationScheme == DerivationScheme.BIP44 -> computeBIP44Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
                    prefix == DeterministicWallet.xpub && derivationScheme == DerivationScheme.BIP49 -> computeBIP49Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
                    prefix == DeterministicWallet.ypub && derivationScheme == DerivationScheme.BIP49 -> computeBIP49Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
                    prefix == DeterministicWallet.zpub && derivationScheme == DerivationScheme.BIP84 -> computeBIP84Address(pub.publicKey, Block.LivenetGenesisBlock.hash)
                    else -> error("invalid prefix $prefix")
                }
                address
            }
        }
    }
}