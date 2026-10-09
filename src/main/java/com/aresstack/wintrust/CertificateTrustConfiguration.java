package com.aresstack.wintrust;

/**
 * Configures <em>which</em> certificate sources Java trusts during the TLS handshake.
 *
 * <p>Certificate trust is deliberately kept independent of proxy <em>resolution</em> (how an
 * application reaches the network, see {@code com.aresstack:win-proxy-java}). A corporate
 * TLS-intercepting proxy can be discovered perfectly and still make every HTTPS request fail with
 * {@code PKIX path building failed}, because the proxy's private CA lives in the Windows certificate
 * store but not in the JVM's bundled {@code cacerts}.</p>
 *
 * <p>The three sources are additive trust anchors; a server chain is accepted when <em>any</em>
 * enabled source accepts it:</p>
 * <ul>
 *   <li>{@code useJvmDefault} &mdash; the JVM's default truststore ({@code cacerts}, or whatever
 *       {@code javax.net.ssl.trustStore} points to).</li>
 *   <li>{@code useWindowsRoot} &mdash; the {@code Windows-ROOT} store (Trusted Root Certification
 *       Authorities) exposed by Java's built-in {@code SunMSCAPI} provider. Needs no external
 *       process.</li>
 *   <li>{@code useWindowsCaStores} &mdash; the Windows Root <em>and</em> Intermediate CA stores in
 *       both the {@code LocalMachine} and {@code CurrentUser} scopes, exported through an inline
 *       {@code powershell.exe -Command}. The Root stores supply trust anchors; the Intermediate store
 *       (which {@code SunMSCAPI} does not expose) supplies chain-building material only. This is what
 *       lets PKIX build a chain when a TLS-intercepting proxy omits the intermediate certificate from
 *       the handshake, without ever trusting an intermediate whose root is not trusted.</li>
 * </ul>
 *
 * <p>Instances are immutable. Use {@link #defaults()} for all three sources, or
 * {@link #builder()} to switch individual sources off.</p>
 */
public final class CertificateTrustConfiguration {

    private final boolean useJvmDefault;
    private final boolean useWindowsRoot;
    private final boolean useWindowsCaStores;
    private final long windowsExportTimeoutSeconds;

    /**
     * Same as the four-argument constructor with the default PowerShell timeout
     * ({@link WindowsCertificateStores#DEFAULT_TIMEOUT_SECONDS}).
     *
     * @param useJvmDefault      trust the JVM default truststore
     * @param useWindowsRoot     trust the {@code Windows-ROOT} store via {@code SunMSCAPI}
     * @param useWindowsCaStores use the Windows Root and Intermediate CA stores exported via PowerShell
     *                           (Root certificates as trust anchors, Intermediate certificates as
     *                           path-building material only)
     */
    public CertificateTrustConfiguration(boolean useJvmDefault, boolean useWindowsRoot, boolean useWindowsCaStores) {
        this(useJvmDefault, useWindowsRoot, useWindowsCaStores, WindowsCertificateStores.DEFAULT_TIMEOUT_SECONDS);
    }

    /**
     * @param useJvmDefault               trust the JVM default truststore
     * @param useWindowsRoot              trust the {@code Windows-ROOT} store via {@code SunMSCAPI}
     * @param useWindowsCaStores          use the Windows Root and Intermediate CA stores exported via
     *                                    PowerShell (Root certificates as trust anchors, Intermediate
     *                                    certificates as path-building material only)
     * @param windowsExportTimeoutSeconds how long the PowerShell export may run before it is killed and
     *                                    reported as failed; must be positive
     * @throws IllegalArgumentException when {@code windowsExportTimeoutSeconds} is not positive
     */
    public CertificateTrustConfiguration(boolean useJvmDefault, boolean useWindowsRoot, boolean useWindowsCaStores,
                                         long windowsExportTimeoutSeconds) {
        if (windowsExportTimeoutSeconds <= 0) {
            throw new IllegalArgumentException(
                    "windowsExportTimeoutSeconds must be positive, got " + windowsExportTimeoutSeconds);
        }
        this.useJvmDefault = useJvmDefault;
        this.useWindowsRoot = useWindowsRoot;
        this.useWindowsCaStores = useWindowsCaStores;
        this.windowsExportTimeoutSeconds = windowsExportTimeoutSeconds;
    }

    /**
     * @return the default trust configuration: JVM {@code cacerts} <em>plus</em> {@code Windows-ROOT}
     *         <em>plus</em> the Windows Root/Intermediate CA stores. This is the combination that makes
     *         corporate TLS-intercepting proxies work out of the box.
     */
    public static CertificateTrustConfiguration defaults() {
        return new CertificateTrustConfiguration(true, true, true);
    }

    /**
     * @return a configuration that trusts only the JVM default truststore, i.e. plain JVM behaviour
     *         with the diagnostics of this library. Never starts PowerShell.
     */
    public static CertificateTrustConfiguration jvmDefaultOnly() {
        return new CertificateTrustConfiguration(true, false, false);
    }

    /**
     * @return a builder pre-populated with {@link #defaults()}
     */
    public static Builder builder() {
        return new Builder();
    }

    public boolean isUseJvmDefault() {
        return useJvmDefault;
    }

    public boolean isUseWindowsRoot() {
        return useWindowsRoot;
    }

    public boolean isUseWindowsCaStores() {
        return useWindowsCaStores;
    }

    /**
     * @return the timeout for the PowerShell export of the Windows Root/Intermediate CA stores, in
     *         seconds (default {@link WindowsCertificateStores#DEFAULT_TIMEOUT_SECONDS})
     */
    public long getWindowsExportTimeoutSeconds() {
        return windowsExportTimeoutSeconds;
    }

    /**
     * @return {@code true} when at least one trust source is enabled
     */
    public boolean isAnySourceEnabled() {
        return useJvmDefault || useWindowsRoot || useWindowsCaStores;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof CertificateTrustConfiguration)) {
            return false;
        }
        CertificateTrustConfiguration that = (CertificateTrustConfiguration) other;
        return useJvmDefault == that.useJvmDefault
                && useWindowsRoot == that.useWindowsRoot
                && useWindowsCaStores == that.useWindowsCaStores
                && windowsExportTimeoutSeconds == that.windowsExportTimeoutSeconds;
    }

    @Override
    public int hashCode() {
        int result = useJvmDefault ? 1 : 0;
        result = 31 * result + (useWindowsRoot ? 1 : 0);
        result = 31 * result + (useWindowsCaStores ? 1 : 0);
        result = 31 * result + (int) (windowsExportTimeoutSeconds ^ (windowsExportTimeoutSeconds >>> 32));
        return result;
    }

    @Override
    public String toString() {
        return "CertificateTrustConfiguration{jvmDefault=" + useJvmDefault
                + ", windowsRoot=" + useWindowsRoot
                + ", windowsCaStores=" + useWindowsCaStores
                + ", windowsExportTimeoutSeconds=" + windowsExportTimeoutSeconds + '}';
    }

    /**
     * Builder for {@link CertificateTrustConfiguration}. All sources start enabled.
     */
    public static final class Builder {
        private boolean useJvmDefault = true;
        private boolean useWindowsRoot = true;
        private boolean useWindowsCaStores = true;
        private long windowsExportTimeoutSeconds = WindowsCertificateStores.DEFAULT_TIMEOUT_SECONDS;

        private Builder() {
        }

        public Builder useJvmDefault(boolean useJvmDefault) {
            this.useJvmDefault = useJvmDefault;
            return this;
        }

        public Builder useWindowsRoot(boolean useWindowsRoot) {
            this.useWindowsRoot = useWindowsRoot;
            return this;
        }

        public Builder useWindowsCaStores(boolean useWindowsCaStores) {
            this.useWindowsCaStores = useWindowsCaStores;
            return this;
        }

        /**
         * @param seconds how long the PowerShell export may run before it is killed; must be positive.
         *                Raise it on slow machines with very large certificate stores.
         */
        public Builder windowsExportTimeoutSeconds(long seconds) {
            this.windowsExportTimeoutSeconds = seconds;
            return this;
        }

        public CertificateTrustConfiguration build() {
            return new CertificateTrustConfiguration(useJvmDefault, useWindowsRoot, useWindowsCaStores,
                    windowsExportTimeoutSeconds);
        }
    }
}
