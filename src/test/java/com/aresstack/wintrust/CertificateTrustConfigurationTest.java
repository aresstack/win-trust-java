package com.aresstack.wintrust;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
}
