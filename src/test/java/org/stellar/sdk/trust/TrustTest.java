package org.stellar.sdk.trust;

import org.junit.Test;
import org.stellar.sdk.*;
import org.stellar.sdk.responses.AccountResponse;
import org.stellar.sdk.responses.SubmitTransactionResponse;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Scanner;

import static net.i2p.crypto.eddsa.Utils.bytesToHex;
import static org.junit.Assert.assertEquals;

public class TrustTest {
    /*
    Account 1 - From
    ----------------
    encoded seed:
    SAV4O6KS2F6ZKVKRBDY2CC3AAP2NQUIN4OIET2BGSZYV6FX7OJMWPBV4

    account id:
    GCB4PXH4V4WJVLOGCUBOL5JTCL3GIXRJVQJNLFJMN2CGB5TIT6Y6PQMB

    Account 2 - To
    --------------
    encoded seed:
    SDAEFQN6O4EETVPZWKL74KHT3WI5KVYGDAXXGQ5D5KZLVGT4MMHSZMVJ

    account id:
    GCFHIPURU3JLYMREI4FGTZK5YWMM4M4GH45UEVI4RUW6VLMH7OY5YECK
 */

    final String SECRET_SEED_HASH_OF_FROM = "SAV4O6KS2F6ZKVKRBDY2CC3AAP2NQUIN4OIET2BGSZYV6FX7OJMWPBV4";
    final String ACCOUNT_ID_HASH_OF_FROM = "GCB4PXH4V4WJVLOGCUBOL5JTCL3GIXRJVQJNLFJMN2CGB5TIT6Y6PQMB";
    final String ACCOUNT_ID_HASH_OF_TO = "GCFHIPURU3JLYMREI4FGTZK5YWMM4M4GH45UEVI4RUW6VLMH7OY5YECK";

    final String HORIZON_TESTNET_URL = "https://horizon-testnet.stellar.org";

    @Test
    public void generateKeyPairAndCreateAccountOnTestNet() throws IOException {
        // reference @ https://www.stellar.org/developers/guides/get-started/create-account.html

        KeyPair pair = KeyPair.random();

        System.out.println(new String(pair.getSecretSeed()));
        // e.g. SAV76USXIJOBMEQXPANUOQM6F5LIOTLPDIDVRJBFFE2MDJXG24TAPUU7
        System.out.println(pair.getAccountId());
        // e.g. GCFXHS4GXL6BVUCXBWXGTITROWLVYXQKQLF4YH5O5JT3YZXCYPAFBJZB

        String friendbotUrl = String.format(
                "https://friendbot.stellar.org/?addr=%s",
                pair.getAccountId());
        InputStream response = new URL(friendbotUrl).openStream();
        String body = new Scanner(response, "UTF-8").useDelimiter("\\A").next();
        System.out.println("SUCCESS! You have a new account :)\n" + body);
    }

    @Test
    public void submitTransaction() throws IOException {
        Network.useTestNetwork();
        Server server = new Server(HORIZON_TESTNET_URL);

        KeyPair source = KeyPair.fromSecretSeed(SECRET_SEED_HASH_OF_FROM);
        KeyPair destination = KeyPair.fromAccountId(ACCOUNT_ID_HASH_OF_TO);

        // First, check to make sure that the destination account exists.
        // You could skip this, but if the account does not exist, you will be charged
        // the transaction fee when the transaction fails.
        // It will throw HttpResponseException if account does not exist or there was another error.
        server.accounts().account(destination);

        // If there was no error, load up-to-date information on your account.
        AccountResponse sourceAccount = server.accounts().account(source);

        // Start building the transaction.
        String timeNow = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        final long TEN_SECONDS_TIMEOUT = 10 * 1000;
        Transaction transaction = new Transaction.Builder(sourceAccount)
                .addOperation(new PaymentOperation.Builder(destination, new AssetTypeNative(), "10").build())
                // A memo allows you to add your own metadata to a transaction. It's
                // optional and does not affect how Stellar treats the transaction.
                .addMemo(Memo.text(String.format("%s by JNJ", timeNow)))
                .setTimeout(TEN_SECONDS_TIMEOUT)
                .build();

        // Hash the transaction
        System.out.println("TX hash: \n" + bytesToHex(transaction.hash()));

        // Sign the transaction to prove you are actually the person sending it.
        transaction.sign(source);

        // And finally, send it off to Stellar!
        try {
            SubmitTransactionResponse response = server.submitTransaction(transaction);
            System.out.println("Success!");
            System.out.println(response);
        } catch (Exception e) {
            System.out.println("Something went wrong!");
            System.out.println(e.getMessage());
            // If the result is unknown (no response body, timeout etc.) we simply resubmit
            // already built transaction:
            // SubmitTransactionResponse response = server.submitTransaction(transaction);
        }
    }

    @Test
    public void hashTransaction() throws IOException {
        Network.useTestNetwork();
        Server server = new Server(HORIZON_TESTNET_URL);

        KeyPair source = KeyPair.fromSecretSeed(SECRET_SEED_HASH_OF_FROM);
        KeyPair destination = KeyPair.fromAccountId(ACCOUNT_ID_HASH_OF_TO);

        // First, check to make sure that the destination account exists.
        // You could skip this, but if the account does not exist, you will be charged
        // the transaction fee when the transaction fails.
        // It will throw HttpResponseException if account does not exist or there was another error.
        server.accounts().account(destination);

        // If there was no error, load up-to-date information on your account.
        AccountResponse sourceAccount = server.accounts().account(source);

        // Start building the transaction.
        final long TEN_SECONDS_TIMEOUT = 10 * 1000;
        Transaction transaction = new Transaction.Builder(sourceAccount)
                .addOperation(new PaymentOperation.Builder(destination, new AssetTypeNative(), "10").build())
                // A memo allows you to add your own metadata to a transaction. It's
                // optional and does not affect how Stellar treats the transaction.
                .addMemo(Memo.text("test by JNJ"))
                .setTimeout(TEN_SECONDS_TIMEOUT)
                .buildForTestOnly();

        // Hash the transaction
        String hashString = bytesToHex(transaction.hash());
        System.out.println("TX hash: \n" + hashString);

        assertEquals("a60d309e0a51eb152df9785580504bbd120fc32793759b23c31d08afde99bc0b", hashString);
    }

    @Test
    public void testAccountIdOfFromDecoding() {
        assertEquals("GCB4PXH4V4WJVLOGCUBOL5JTCL3GIXRJVQJNLFJMN2CGB5TIT6Y6PQMB", ACCOUNT_ID_HASH_OF_FROM);

        byte[] decodedInBase32 = StrKey.base32Encoding.decode(java.nio.CharBuffer.wrap(ACCOUNT_ID_HASH_OF_FROM));
        assertEquals("[48, -125, -57, -36, -4, -81, 44, -102, -83, -58, 21, 2, -27, -11, 51, 18, -10, 100, 94, 41, -84, 18, -43, -107, 44, 110, -124, 96, -10, 104, -97, -79, -25, -63, -127]", Arrays.toString(decodedInBase32));

        byte[] payload = Arrays.copyOfRange(decodedInBase32, 0, decodedInBase32.length-2);
        assertEquals("[48, -125, -57, -36, -4, -81, 44, -102, -83, -58, 21, 2, -27, -11, 51, 18, -10, 100, 94, 41, -84, 18, -43, -107, 44, 110, -124, 96, -10, 104, -97, -79, -25]", Arrays.toString(payload));

        byte[] data = Arrays.copyOfRange(payload, 1, payload.length);
        assertEquals("[-125, -57, -36, -4, -81, 44, -102, -83, -58, 21, 2, -27, -11, 51, 18, -10, 100, 94, 41, -84, 18, -43, -107, 44, 110, -124, 96, -10, 104, -97, -79, -25]", Arrays.toString(data));

        byte[] checksum = Arrays.copyOfRange(decodedInBase32, decodedInBase32.length-2, decodedInBase32.length);
        assertEquals("[-63, -127]", Arrays.toString(checksum));

        byte[] decoded = StrKey.decodeStellarAccountId(ACCOUNT_ID_HASH_OF_FROM);
        assertEquals("[-125, -57, -36, -4, -81, 44, -102, -83, -58, 21, 2, -27, -11, 51, 18, -10, 100, 94, 41, -84, 18, -43, -107, 44, 110, -124, 96, -10, 104, -97, -79, -25]", Arrays.toString(decoded));
    }

    @Test
    public void testAccountIdOfToDecoding() {
        assertEquals("GCFHIPURU3JLYMREI4FGTZK5YWMM4M4GH45UEVI4RUW6VLMH7OY5YECK", ACCOUNT_ID_HASH_OF_TO);

        byte[] decoded = StrKey.decodeStellarAccountId(ACCOUNT_ID_HASH_OF_TO);
        assertEquals("[-118, 116, 62, -111, -90, -46, -68, 50, 36, 71, 10, 105, -27, 93, -59, -104, -50, 51, -122, 63, 59, 66, 85, 28, -115, 45, -22, -83, -121, -5, -79, -36]", Arrays.toString(decoded));
    }
}
