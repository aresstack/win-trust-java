package com.aresstack.wintrust;

import org.junit.jupiter.api.Test;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CompositeX509TrustManagerTest {

    private static final X509Certificate[] CHAIN = new X509Certificate[0];

    @Test
    void acceptsWhenAnyDelegateAccepts() throws CertificateException {
        RecordingTrustManager rejecting = new RecordingTrustManager(false);
        RecordingTrustManager accepting = new RecordingTrustManager(true);
        CompositeX509TrustManager composite = new CompositeX509TrustManager(
                Arrays.<X509TrustManager>asList(rejecting, accepting));

        composite.checkServerTrusted(CHAIN, "RSA");
        composite.checkClientTrusted(CHAIN, "RSA");

        assertEquals(1, rejecting.serverChecks, "the rejecting delegate is consulted first");
        assertEquals(1, accepting.serverChecks, "the accepting delegate decides");
        assertEquals(1, accepting.clientChecks);
    }

    @Test
    void stopsAtTheFirstAcceptingDelegate() throws CertificateException {
        RecordingTrustManager first = new RecordingTrustManager(true);
        RecordingTrustManager second = new RecordingTrustManager(true);
        CompositeX509TrustManager composite = new CompositeX509TrustManager(
                Arrays.<X509TrustManager>asList(first, second));

        composite.checkServerTrusted(CHAIN, "RSA");

        assertEquals(1, first.serverChecks);
        assertEquals(0, second.serverChecks, "later delegates are not consulted once one accepted");
    }

    @Test
    void rethrowsTheLastRejectionWhenEveryDelegateRejects() {
        RecordingTrustManager first = new RecordingTrustManager(false);
        RecordingTrustManager second = new RecordingTrustManager(false);
        CompositeX509TrustManager composite = new CompositeX509TrustManager(
                Arrays.<X509TrustManager>asList(first, second));

        CertificateException thrown = assertThrows(CertificateException.class,
                () -> composite.checkServerTrusted(CHAIN, "RSA"));

        assertSame(second.lastException, thrown, "the last delegate's exception surfaces");
        assertEquals(1, first.serverChecks);
        assertEquals(1, second.serverChecks);
    }

    @Test
    void rejectsWithoutDelegates() {
        CompositeX509TrustManager composite =
                new CompositeX509TrustManager(Collections.<X509TrustManager>emptyList());

        assertThrows(CertificateException.class, () -> composite.checkServerTrusted(CHAIN, "RSA"));
        assertThrows(CertificateException.class, () -> composite.checkClientTrusted(CHAIN, "RSA"));
        assertEquals(0, composite.getAcceptedIssuers().length);
    }

    @Test
    void aggregatesAcceptedIssuersOfAllDelegatesAndToleratesNull() throws Exception {
        X509Certificate certificate = WindowsCertificateStores
                .parseCertificates(TestCertificates.TEST_CA_BASE64).get(0);
        RecordingTrustManager withIssuer = new RecordingTrustManager(true);
        withIssuer.issuers = new X509Certificate[]{certificate};
        RecordingTrustManager withoutIssuers = new RecordingTrustManager(true);
        withoutIssuers.issuers = null;
        CompositeX509TrustManager composite = new CompositeX509TrustManager(
                Arrays.<X509TrustManager>asList(withIssuer, withoutIssuers, withIssuer));

        X509Certificate[] issuers = composite.getAcceptedIssuers();

        assertEquals(2, issuers.length, "every delegate's issuers are listed, null arrays are skipped");
        assertSame(certificate, issuers[0]);
    }

    @Test
    void delegateListIsCopiedAndUnmodifiable() {
        List<X509TrustManager> source = new ArrayList<X509TrustManager>();
        source.add(new RecordingTrustManager(true));
        CompositeX509TrustManager composite = new CompositeX509TrustManager(source);
        source.clear();

        assertEquals(1, composite.getDelegates().size());
        assertThrows(UnsupportedOperationException.class, () -> composite.getDelegates().clear());
        assertTrue(composite.getDelegates().get(0) instanceof RecordingTrustManager);
    }

    private static final class RecordingTrustManager implements X509TrustManager {

        private final boolean accept;
        int serverChecks;
        int clientChecks;
        CertificateException lastException;
        X509Certificate[] issuers = new X509Certificate[0];

        RecordingTrustManager(boolean accept) {
            this.accept = accept;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            clientChecks++;
            if (!accept) {
                lastException = new CertificateException("client rejected by " + this);
                throw lastException;
            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            serverChecks++;
            if (!accept) {
                lastException = new CertificateException("server rejected by " + this);
                throw lastException;
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return issuers;
        }
    }
}
