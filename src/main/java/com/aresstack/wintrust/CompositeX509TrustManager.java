package com.aresstack.wintrust;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Accepts a certificate chain when <em>any</em> of the delegate trust managers accepts it.
 *
 * <p>Each delegate is a regular PKIX {@link X509TrustManager} built from one trust source (JVM
 * {@code cacerts}, {@code Windows-ROOT}, exported Windows CA stores). Validation is therefore never
 * weakened: a chain still has to validate against the anchors of at least one source. When every
 * delegate rejects the chain, the exception of the last delegate is rethrown.</p>
 */
final class CompositeX509TrustManager implements X509TrustManager {

    private final List<X509TrustManager> delegates;

    CompositeX509TrustManager(List<X509TrustManager> delegates) {
        this.delegates = Collections.unmodifiableList(new ArrayList<X509TrustManager>(delegates));
    }

    List<X509TrustManager> getDelegates() {
        return delegates;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateException last = null;
        for (X509TrustManager delegate : delegates) {
            try {
                delegate.checkClientTrusted(chain, authType);
                return;
            } catch (CertificateException ex) {
                last = ex;
            }
        }
        throw last != null ? last
                : new CertificateException("No trust manager accepted the client certificate chain.");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateException last = null;
        for (X509TrustManager delegate : delegates) {
            try {
                delegate.checkServerTrusted(chain, authType);
                return;
            } catch (CertificateException ex) {
                last = ex;
            }
        }
        throw last != null ? last
                : new CertificateException("No trust manager accepted the server certificate chain.");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        List<X509Certificate> issuers = new ArrayList<X509Certificate>();
        for (X509TrustManager delegate : delegates) {
            X509Certificate[] certificates = delegate.getAcceptedIssuers();
            if (certificates != null) {
                for (X509Certificate certificate : certificates) {
                    issuers.add(certificate);
                }
            }
        }
        return issuers.toArray(new X509Certificate[issuers.size()]);
    }
}
