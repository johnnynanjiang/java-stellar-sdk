package org.stellar.sdk;

import org.junit.Assert;
import org.junit.Test;

import static org.stellar.sdk.SLIP0010Ed25519PrivateKeyTest.deriveEd25519PrivateKey;

/*  Test case reference
    https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md#key-derivation-for-ed25519
 */
public class SEP0005Test {

    private final String bip39Seed = "e4a5a632e70943ae7f07659df1332160937fad82587216a4c64315a0fb39497ee4a01f76ddab4cba68147977f3a147b6ad584c41808e8238a07f6cc4b582f186";

    @Test
    public void test_m_44_148() {
        Assert.assertEquals(
                "e0eec84fe165cd427cb7bc9b6cfdef0555aa1cb6f9043ff1fe986c3c8ddd22e3",
                deriveEd25519PrivateKey(bip39Seed, 44, 148)
        );
    }

    @Test
    public void test_m_44_148_0() {
        Assert.assertEquals(
                "4d691bc19b44a1383b1a0a130aaca3e05c3c1a371dbe45930ef9b761f7a74691",
                deriveEd25519PrivateKey(bip39Seed, 44, 148, 0)
        );
    }

    @Test
    public void test_m_44_148_0_0_0() {
        Assert.assertEquals(
                "5bfacd5e07f3a942f565be36e3631ddb6157815f03efd63444ea1cb024f03919",
                deriveEd25519PrivateKey(bip39Seed, 44, 148, 0, 0, 0)
        );
    }

    @Test
    public void test_m_44_148_1_0_0() {
        Assert.assertEquals(
                "6bd01aa6186c155981e673fb892a7901c5e000a4efe0496699c77694868de373",
                deriveEd25519PrivateKey(bip39Seed, 44, 148, 1, 0, 0)
        );
    }
}