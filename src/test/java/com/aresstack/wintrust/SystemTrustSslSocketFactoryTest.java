package com.aresstack.wintrust;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;

import javax.net.ssl.SSLSocketFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SystemTrustSslSocketFactoryTest {

    private static final CertificateTrustConfiguration NOTHING = new CertificateTrustConfiguration(false, false, false);

    @BeforeEach
    void clearCache() {
        SystemTrustSslSocketFactory.clearCache();
    }

    @Test
    void jvmDefaultOnlyBuildsACombinedContextOnAnyPlatform() {
        SystemTrustSslSocketFactory.Result result =
                SystemTrustSslSocketFactory.build(CertificateTrustConfiguration.jvmDefaultOnly());

        assertTrue(result.isJvmDefaultTrusted());
        assertFalse(result.isWindowsRootTrusted());
        assertFalse(result.isWindowsCaStoresTrusted());
        assertEquals(0, result.getWindowsExportedCertificateCount());
        assertFalse(result.isFallbackToJvmDefault());
        assertNotNull(result.getSocketFactory());
        assertNotNull(result.getSslContext());
        assertNotNull(result.getTrustManager());
        assertNotSame(SSLSocketFactory.getDefault(), result.getSocketFactory());
        assertTrue(result.getTrustManager() instanceof CompositeX509TrustManager);
        assertTrue(result.getTrustManager().getAcceptedIssuers().length > 0,
                "the JVM truststore contributes its root certificates");
        assertTrue(result.getDiagnostics().contains("JVM default truststore (cacerts) loaded."), result.getDiagnostics().toString());
    }

    @Test
    void nothingEnabledFallsBackToTheJvmDefaultFactory() {
        SystemTrustSslSocketFactory.Result result = SystemTrustSslSocketFactory.build(NOTHING);

        assertTrue(result.isFallbackToJvmDefault());
        assertFalse(result.isJvmDefaultTrusted());
        assertNotNull(result.getSocketFactory());
        assertNotNull(result.getSslContext());
        assertNotNull(result.getTrustManager(), "the fallback still exposes the JVM default trust manager");
        assertTrue(result.getDiagnostics().contains("No trust source is enabled."), result.getDiagnostics().toString());
        assertTrue(result.getDiagnostics().get(result.getDiagnostics().size() - 1)
                .startsWith("No trust source produced a trust manager"), result.getDiagnostics().toString());
    }

    @Test
    void nullConfigurationMeansDefaults() {
        SystemTrustSslSocketFactory.Result viaNull = SystemTrustSslSocketFactory.build(null);
        SystemTrustSslSocketFactory.Result viaDefaults =
                SystemTrustSslSocketFactory.build(CertificateTrustConfiguration.defaults());

        assertSame(viaNull, viaDefaults);
        assertTrue(viaNull.isJvmDefaultTrusted());
    }

    @Test
    void buildCachesPerConfigurationButCreateDoesNot() {
        CertificateTrustConfiguration jvmOnly = CertificateTrustConfiguration.jvmDefaultOnly();

        SystemTrustSslSocketFactory.Result first = SystemTrustSslSocketFactory.build(jvmOnly);
        SystemTrustSslSocketFactory.Result second = SystemTrustSslSocketFactory.build(
                new CertificateTrustConfiguration(true, false, false));
        SystemTrustSslSocketFactory.Result other = SystemTrustSslSocketFactory.build(NOTHING);
        SystemTrustSslSocketFactory.Result fresh = SystemTrustSslSocketFactory.create(jvmOnly);

        assertSame(first, second, "equal configurations share one cached result");
        assertNotSame(first, other);
        assertNotSame(first, fresh, "create() always builds anew");
        assertSame(first, SystemTrustSslSocketFactory.build(jvmOnly), "create() does not replace the cache");

        SystemTrustSslSocketFactory.clearCache();
        assertNotSame(first, SystemTrustSslSocketFactory.build(jvmOnly));
    }

    @Test
    void diagnosticsAndResultAreImmutable() {
        SystemTrustSslSocketFactory.Result result =
                SystemTrustSslSocketFactory.build(CertificateTrustConfiguration.jvmDefaultOnly());

        org.junit.jupiter.api.Assertions.assertThrows(UnsupportedOperationException.class,
                () -> result.getDiagnostics().add("x"));
        assertTrue(result.toString().contains("jvmDefaultTrusted=true"), result.toString());
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void windowsRootIsReportedUnavailableOffWindows() {
        SystemTrustSslSocketFactory.Result result =
                SystemTrustSslSocketFactory.build(new CertificateTrustConfiguration(false, true, false));

        assertFalse(result.isWindowsRootTrusted());
        assertTrue(result.isFallbackToJvmDefault());
        assertTrue(containsPrefix(result, "Windows-ROOT store unavailable:"), result.getDiagnostics().toString());
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void windowsCaStoresContributeNothingOffWindows() {
        SystemTrustSslSocketFactory.Result result =
                SystemTrustSslSocketFactory.build(new CertificateTrustConfiguration(true, false, true));

        assertTrue(result.isJvmDefaultTrusted());
        assertFalse(result.isWindowsCaStoresTrusted());
        assertEquals(0, result.getWindowsExportedCertificateCount());
        assertFalse(result.isFallbackToJvmDefault(), "the JVM source alone still yields a combined context");
        assertEquals(0, result.getWindowsRootAnchorCount());
        assertEquals(0, result.getWindowsIntermediateCount());
        assertTrue(result.getDiagnostics().contains("Windows Root/Intermediate CA stores contributed no trust anchors."),
                result.getDiagnostics().toString());
        assertFalse(containsPrefix(result, "Windows Root/Intermediate CA export:"),
                "off Windows the export is skipped silently, there is no error");
    }

    private static boolean containsPrefix(SystemTrustSslSocketFactory.Result result, String prefix) {
        for (String line : result.getDiagnostics()) {
            if (line.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
