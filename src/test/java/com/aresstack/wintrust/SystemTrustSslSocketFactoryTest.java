package com.aresstack.wintrust;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;

import javax.net.ssl.SSLSocketFactory;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
    @DisabledOnOs(OS.WINDOWS) // defaults() enable the PowerShell export; only the opt-in tests may start it
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

    // ── Windows store branches, driven with known certificates on any platform ──

    private static final CertificateTrustConfiguration JVM_PLUS_WINDOWS_CA = CertificateTrustConfiguration.builder()
            .useWindowsRoot(false)
            .build();
    private static final X509Certificate ROOT = TestCertificates.decode(TestCertificates.ROOT_BASE64);
    private static final X509Certificate INTERMEDIATE = TestCertificates.decode(TestCertificates.INTERMEDIATE_BASE64);
    private static final X509Certificate LEAF = TestCertificates.decode(TestCertificates.LEAF_BASE64);

    private static WindowsCertificateStores.Result stores(List<X509Certificate> roots,
                                                          List<X509Certificate> intermediates, String error) {
        return new WindowsCertificateStores.Result(roots, intermediates, error);
    }

    @Test
    void exportedRootAndIntermediateMakeALeafOnlyChainTrustedThroughTheComposite() throws Exception {
        SystemTrustSslSocketFactory.Result result = SystemTrustSslSocketFactory.assemble(JVM_PLUS_WINDOWS_CA,
                stores(Collections.singletonList(ROOT), Collections.singletonList(INTERMEDIATE), null));

        assertTrue(result.isJvmDefaultTrusted());
        assertTrue(result.isWindowsCaStoresTrusted());
        assertFalse(result.isFallbackToJvmDefault());
        assertEquals(1, result.getWindowsRootAnchorCount());
        assertEquals(1, result.getWindowsIntermediateCount());
        assertEquals(2, result.getWindowsExportedCertificateCount());
        assertTrue(result.getDiagnostics().contains(
                "Windows Root/Intermediate CA stores loaded 1 root anchor(s) and 1 intermediate certificate(s)."),
                result.getDiagnostics().toString());
        // cacerts in front of it rejects the private chain; the composite still accepts the server
        // certificate alone, because the Windows delegate completes the chain from the Intermediate store.
        result.getTrustManager().checkServerTrusted(new X509Certificate[]{LEAF}, "RSA");
        assertThrows(CertificateException.class, () -> SystemTrustSslSocketFactory
                .build(CertificateTrustConfiguration.jvmDefaultOnly()).getTrustManager()
                .checkServerTrusted(new X509Certificate[]{LEAF}, "RSA"));
    }

    @Test
    void intermediatesWithoutARootAreIgnoredNotTrusted() {
        SystemTrustSslSocketFactory.Result result = SystemTrustSslSocketFactory.assemble(JVM_PLUS_WINDOWS_CA,
                stores(Collections.<X509Certificate>emptyList(), Collections.singletonList(INTERMEDIATE), null));

        assertFalse(result.isWindowsCaStoresTrusted());
        assertEquals(0, result.getWindowsRootAnchorCount());
        assertEquals(1, result.getWindowsIntermediateCount());
        assertTrue(result.getDiagnostics().contains("Windows Root/Intermediate CA stores contributed no trust anchors; "
                + "1 intermediate certificate(s) ignored because there is no root to anchor them."),
                result.getDiagnostics().toString());
        assertThrows(CertificateException.class,
                () -> result.getTrustManager().checkServerTrusted(new X509Certificate[]{LEAF, INTERMEDIATE}, "RSA"));
    }

    @Test
    void partialExportIsReportedWhileItsCertificatesAreStillUsed() throws Exception {
        SystemTrustSslSocketFactory.Result result = SystemTrustSslSocketFactory.assemble(JVM_PLUS_WINDOWS_CA,
                stores(Collections.singletonList(ROOT), Collections.singletonList(INTERMEDIATE),
                        "Certificate store(s) could not be read: Cert:\\CurrentUser\\CA: denied"));

        assertTrue(result.isWindowsCaStoresTrusted());
        assertTrue(result.getDiagnostics().contains(
                "Windows Root/Intermediate CA export: Certificate store(s) could not be read: Cert:\\CurrentUser\\CA: denied"),
                result.getDiagnostics().toString());
        result.getTrustManager().checkServerTrusted(new X509Certificate[]{LEAF}, "RSA");
    }

    @Test
    void failedExportWithoutCertificatesLeavesOnlyTheOtherSources() {
        SystemTrustSslSocketFactory.Result result = SystemTrustSslSocketFactory.assemble(JVM_PLUS_WINDOWS_CA,
                stores(Collections.<X509Certificate>emptyList(), Collections.<X509Certificate>emptyList(),
                        "Windows certificate export failed: Cannot run program \"powershell.exe\""));

        assertTrue(result.isJvmDefaultTrusted());
        assertFalse(result.isWindowsCaStoresTrusted());
        assertFalse(result.isFallbackToJvmDefault());
        assertTrue(result.getDiagnostics().contains(
                "Windows Root/Intermediate CA export: Windows certificate export failed: Cannot run program \"powershell.exe\""),
                result.getDiagnostics().toString());
        assertTrue(result.getDiagnostics().contains("Windows Root/Intermediate CA stores contributed no trust anchors."),
                result.getDiagnostics().toString());
    }
}
