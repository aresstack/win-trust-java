package com.aresstack.wintrust;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateTrustConfigurationTest {

    @Test
    void defaultsEnableAllThreeSources() {
        CertificateTrustConfiguration defaults = CertificateTrustConfiguration.defaults();

        assertTrue(defaults.isUseJvmDefault());
        assertTrue(defaults.isUseWindowsRoot());
        assertTrue(defaults.isUseWindowsCaStores());
        assertTrue(defaults.isAnySourceEnabled());
    }

    @Test
    void jvmDefaultOnlyNeverTouchesWindows() {
        CertificateTrustConfiguration jvmOnly = CertificateTrustConfiguration.jvmDefaultOnly();

        assertTrue(jvmOnly.isUseJvmDefault());
        assertFalse(jvmOnly.isUseWindowsRoot());
        assertFalse(jvmOnly.isUseWindowsCaStores());
    }

    @Test
    void builderStartsFromDefaultsAndSwitchesSourcesOff() {
        CertificateTrustConfiguration configuration = CertificateTrustConfiguration.builder()
                .useWindowsCaStores(false)
                .build();

        assertEquals(new CertificateTrustConfiguration(true, true, false), configuration);
        assertEquals(CertificateTrustConfiguration.defaults(), CertificateTrustConfiguration.builder().build());
    }

    @Test
    void nothingEnabledIsDetectable() {
        assertFalse(new CertificateTrustConfiguration(false, false, false).isAnySourceEnabled());
    }

    @Test
    void equalityAndHashCodeFollowTheThreeFlags() {
        CertificateTrustConfiguration a = new CertificateTrustConfiguration(true, false, true);
        CertificateTrustConfiguration b = new CertificateTrustConfiguration(true, false, true);
        CertificateTrustConfiguration c = new CertificateTrustConfiguration(true, true, true);

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
        assertNotEquals(a.hashCode(), c.hashCode());
        assertNotEquals(a, null);
        assertNotEquals(a, "CertificateTrustConfiguration");
    }

    @Test
    void toStringNamesEverySource() {
        String text = new CertificateTrustConfiguration(true, false, true).toString();

        assertTrue(text.contains("jvmDefault=true"), text);
        assertTrue(text.contains("windowsRoot=false"), text);
        assertTrue(text.contains("windowsCaStores=true"), text);
    }

    @Test
    void exportTimeoutDefaultsTo25SecondsAndIsConfigurable() {
        assertEquals(WindowsCertificateStores.DEFAULT_TIMEOUT_SECONDS,
                CertificateTrustConfiguration.defaults().getWindowsExportTimeoutSeconds());
        assertEquals(25L, CertificateTrustConfiguration.defaults().getWindowsExportTimeoutSeconds());

        CertificateTrustConfiguration slow = CertificateTrustConfiguration.builder()
                .windowsExportTimeoutSeconds(90L)
                .build();

        assertEquals(90L, slow.getWindowsExportTimeoutSeconds());
        assertEquals(new CertificateTrustConfiguration(true, true, true, 90L), slow);
        assertNotEquals(CertificateTrustConfiguration.defaults(), slow, "the timeout is part of the cache key");
        assertNotEquals(CertificateTrustConfiguration.defaults().hashCode(), slow.hashCode());
        assertTrue(slow.toString().contains("windowsExportTimeoutSeconds=90"), slow.toString());
    }

    @Test
    void exportTimeoutMustBePositive() {
        assertThrows(IllegalArgumentException.class,
                () -> new CertificateTrustConfiguration(true, true, true, 0L));
        assertThrows(IllegalArgumentException.class,
                () -> CertificateTrustConfiguration.builder().windowsExportTimeoutSeconds(-1L).build());
    }
}
