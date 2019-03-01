package org.stellar.sdk;

import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.stellar.sdk.SLIP0010Ed25519PrivateKeyTest.deriveEd25519PrivateKey;

public class TrustAddressTest {

    private final String bip39Seed = "7ae6f661157bda6492f6162701e570097fc726b6235011ea5ad09bf04986731ed4d92bc43cbdee047b60ea0dd1b1fa4274377c9bf5bd14ab1982c272d8076f29";

    @Test
    public void testMasterPrivateKeyDerivation() {
        assertEquals(
                "2d4f374ece128e412067b4df6709257a249a7750fc8124262cf8b08a97f24fad",
                deriveEd25519PrivateKey(bip39Seed)
        );
    }

    @Test
    public void testAddressDerivation() {
        SEP0005KeyPairForAccountFromBip39SeedTest.testDerivedAccounts(bip39Seed,
                "m/44'/148'/0' GCRWFRVQP5XS7I4SFCL374VKV6OHJ3L3H3SDVGH7FW73N7LSNYJXOLDK SBH5DSZ4TQK4C4NXXEG4H7X4PMX4KTPATODJZSOWOCGSNMIU5DM2LKAD",
                "m/44'/148'/1' GCYQ5QE47SIJFB7QT65L3E4GFYL52BUXYW4JP6ARPLZH5EAEYLFOAERQ SCX4WJ3SBL4ZVFNWZM75MYGJVA2O6CGR6RSUVBMEWTLQONFPONHH75H2",
                "m/44'/148'/2' GA3CIZJTRBVOTZK34BXSFXYAVCKGBEBZYRLOVXBZSQLMXX6HHHDKKNNQ SAJGZOKBW4EQX3TPMAPD6H3EDNXDBYIZTPUI43UDC7ZJJUILBRUDJTKR"
        );
    }

    @Test
    public void test_m_44_148() {
        Assert.assertEquals(
                "1cf9c883a02479083712dcc6ed7e70657a3cfc156ae3082de96f3f5fc09bd6c4",
                deriveEd25519PrivateKey(bip39Seed, 44, 148)
        );
    }

    @Test
    public void test_m_44_148_0() {
        Assert.assertEquals(
                "4fd1cb3c9c15c171b7b90dc3fefc7b2fc54de09b869cc9d6708d26b114e8d9a5",
                deriveEd25519PrivateKey(bip39Seed, 44, 148, 0)
        );
    }

    @Test
    public void test_m_44_148_1() {
        Assert.assertEquals(
                "afcb27720af99a95b6cb3fd660c9a834ef08d1f4654a8584b4d70734af734e7f",
                deriveEd25519PrivateKey(bip39Seed, 44, 148, 1)
        );
    }

    @Test
    public void test_m_44_148_0_0_0() {
        Assert.assertEquals(
                "090ceb3bfc18a5994df63adb99d9e1ab4efd6e0b99f3cadc307011c88dfe3dcf",
                deriveEd25519PrivateKey(bip39Seed, 44, 148, 0, 0, 0)
        );
    }

    @Test
    public void test_m_44_148_1_0_0() {
        Assert.assertEquals(
                "bcd8e34fc099226b125b0d0efbc1bb06445bf136cdbad7b270f5cfe727bc0b47",
                deriveEd25519PrivateKey(bip39Seed, 44, 148, 1, 0, 0)
        );
    }
}