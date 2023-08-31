package eu.europa.esig.dss.cookbook.example.sources;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.x509.tsp.KeyStoreTSPSource;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Date;

public class KeyStoreTSPSourceTest {

    @Test
    public void test() throws Exception {
        String keyStoreFileName = "src/main/resources/user_a_rsa.p12";
        char[] keyStorePassword = "password".toCharArray();

        // tag::demo[]
        // import eu.europa.esig.dss.enumerations.DigestAlgorithm;
        // import eu.europa.esig.dss.spi.x509.tsp.KeyStoreTSPSource;
        // import java.io.File;
        // import java.nio.file.Files;
        // import java.security.KeyStore;
        // import java.util.Arrays;
        // import java.util.Date;
        File keyStoreFile = new File(keyStoreFileName);

        // instantiate the KeyStore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(Files.newInputStream(keyStoreFile.toPath()), keyStorePassword);

        // instantiate the KeyStoreTSPSource
        KeyStoreTSPSource keyStoreTSPSource = new KeyStoreTSPSource(keyStore, "self-signed-tsa", keyStorePassword);

        // This method allows configuration of digest algorithms to be supported for a timestamp request
        // Default: SHA-224, SHA-256, SHA-384, SHA-512
        keyStoreTSPSource.setAcceptedDigestAlgorithms(Arrays.asList(
                DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512));

        // This method allows definition of a timestamping policy
        // Default: a dummy TSA policy "1.2.3.4" is used
        keyStoreTSPSource.setTsaPolicy("1.2.3.4");

        // This method allows definition of a custom production time of the timestamp
        // Default: the current time is used
        keyStoreTSPSource.setProductionTime(new Date());

        // This method allows definition of a digest algorithm to be used for a signature of the generated time-stamp
        // Default: SHA-256
        keyStoreTSPSource.setTstDigestAlgorithm(DigestAlgorithm.SHA256);

        // This method defines whether hash algorithm used to sign the timestamp shall use a Probabilistic Signature Scheme
        // Default: FALSE (no PSS is used)
        keyStoreTSPSource.setEnablePSS(true);
        // end::demo[]

    }

}