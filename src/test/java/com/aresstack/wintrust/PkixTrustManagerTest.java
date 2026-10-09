package com.aresstack.wintrust;

import org.junit.jupiter.api.Test;

import javax.net.ssl.X509TrustManager;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Locks down how the Windows store export is turned into trust: Root-store certificates are the
 * only trust anchors, Intermediate-store certificates are chain-building material. The chain used
 * here is {@code root -> intermediate -> leaf} from {@link TestCertificates}.
 */
class PkixTrustManagerTest {

    private static final X509Certificate ROOT = TestCertificates.decode(TestCertificates.ROOT_BASE64);
    private static final X509Certificate INTERMEDIATE = TestCertificates.decode(TestCertificates.INTERMEDIATE_BASE64);
    private static final X509Certificate LEAF = TestCertificates.decode(TestCertificates.LEAF_BASE64);
    private static final X509Certificate UNRELATED_CA = TestCertificates.decode(TestCertificates.TEST_CA_BASE64);

    @Test
    void intermediateFromTheStoreCompletesAChainTheServerLeftIncomplete() throws Exception {
        // The TLS-intercepting-proxy case: the handshake carries only the leaf, the intermediate is
        // in the Windows Intermediate store, the root in the Windows Root store.
        X509TrustManager trust = SystemTrustSslSocketFactory.createPkixTrustManager(
                Collections.singletonList(ROOT), Collections.singletonList(INTERMEDIATE));

        trust.checkServerTrusted(new X509Certificate[]{LEAF}, "RSA");
    }

    @Test
    void withoutTheIntermediateTheIncompleteChainIsRejected() throws Exception {
        X509TrustManager trust = SystemTrustSslSocketFactory.createPkixTrustManager(
                Collections.singletonList(ROOT), Collections.<X509Certificate>emptyList());

        assertThrows(CertificateException.class,
                () -> trust.checkServerTrusted(new X509Certificate[]{LEAF}, "RSA"),
                "a leaf without its intermediate cannot be validated against the root alone");
        // ... while a complete chain from the handshake still validates.
        trust.checkServerTrusted(new X509Certificate[]{LEAF, INTERMEDIATE}, "RSA");
    }

    @Test
    void anIntermediateIsNeverATrustAnchor() throws Exception {
        // Codex review finding: the Windows Intermediate store is a cache Windows fills from every
        // chain it sees. An intermediate whose root is NOT trusted must not make its leaves trusted.
        X509TrustManager trust = SystemTrustSslSocketFactory.createPkixTrustManager(
                Collections.singletonList(UNRELATED_CA), Collections.singletonList(INTERMEDIATE));

        assertThrows(CertificateException.class,
                () -> trust.checkServerTrusted(new X509Certificate[]{LEAF}, "RSA"));
        assertThrows(CertificateException.class,
                () -> trust.checkServerTrusted(new X509Certificate[]{LEAF, INTERMEDIATE}, "RSA"));
        assertThrows(CertificateException.class,
                () -> trust.checkServerTrusted(new X509Certificate[]{LEAF, INTERMEDIATE, ROOT}, "RSA"),
                "even a complete chain is rejected when its root is not an anchor");
    }

    @Test
    void acceptedIssuersAreTheAnchorsOnly() throws Exception {
        X509TrustManager trust = SystemTrustSslSocketFactory.createPkixTrustManager(
                Arrays.asList(ROOT, UNRELATED_CA), Collections.singletonList(INTERMEDIATE));

        List<X509Certificate> issuers = Arrays.asList(trust.getAcceptedIssuers());

        assertEquals(2, issuers.size());
        assertEquals(true, issuers.contains(ROOT));
        assertEquals(true, issuers.contains(UNRELATED_CA));
        assertEquals(false, issuers.contains(INTERMEDIATE), "intermediates are not advertised as anchors");
    }

    @Test
    void anchorsAreRequired() {
        assertThrows(GeneralSecurityException.class, () -> SystemTrustSslSocketFactory.createPkixTrustManager(
                Collections.<X509Certificate>emptyList(), Collections.singletonList(INTERMEDIATE)));
    }

    @Test
    void theExportedStoresFeedTheTrustManagerTheSameWay() throws Exception {
        // End to end through the parser: ROOT lines become anchors, CA lines become intermediates.
        WindowsCertificateStores.Result stores = WindowsCertificateStores.parse(
                WindowsCertificateStores.ROOT_MARKER + TestCertificates.ROOT_BASE64 + "\r\n"
                        + WindowsCertificateStores.INTERMEDIATE_MARKER + TestCertificates.INTERMEDIATE_BASE64 + "\r\n");
        X509TrustManager trust = SystemTrustSslSocketFactory.createPkixTrustManager(
                stores.getRootCertificates(), stores.getIntermediateCertificates());

        trust.checkServerTrusted(new X509Certificate[]{LEAF}, "RSA");
        assertEquals(1, trust.getAcceptedIssuers().length);
    }
}
