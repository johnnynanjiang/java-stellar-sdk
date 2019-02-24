package org.stellar.sdk;

import org.junit.Test;

import static org.junit.Assert.*;

public class AddressTest {

    private final String bip39Seed = "7ae6f661157bda6492f6162701e570097fc726b6235011ea5ad09bf04986731ed4d92bc43cbdee047b60ea0dd1b1fa4274377c9bf5bd14ab1982c272d8076f29";

    @Test
    public void testMasterPrivateKeyDerivation() {
        assertEquals(
                "2d4f374ece128e412067b4df6709257a249a7750fc8124262cf8b08a97f24fad",
                SLIP0010Ed25519PrivateKeyTest.deriveEd25519PrivateKey(bip39Seed)
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
}