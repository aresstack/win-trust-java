package com.aresstack.wintrust;

/**
 * A self-signed test CA certificate (CN=win-trust-java test CA, O=AresStack) as a single line of
 * Base64-encoded DER, exactly the shape the PowerShell export prints per certificate.
 */
final class TestCertificates {

    static final String TEST_CA_BASE64 =
            "MIIDSzCCAjOgAwIBAgIUD3o0HMIJw4zMZhThIPghTDR37QswDQYJKoZIhvcNAQELBQAwNTEfMB0GA1UEAwwWd2luLXRydXN0LWph"
            + "dmEgdGVzdCBDQTESMBAGA1UECgwJQXJlc1N0YWNrMB4XDTI2MTAwOTIxNDA0NVoXDTM2MTAwNjIxNDA0NVowNTEfMB0GA1UEAwwW"
            + "d2luLXRydXN0LWphdmEgdGVzdCBDQTESMBAGA1UECgwJQXJlc1N0YWNrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
            + "uapz8hI8HxMg763ttLi6JNXIZB1GYSO5YtX1zGIF4QPk36It/PxcZcQ2VBhYOlFpO5ZPeCuxiB92dmw6Jg45vp6Fgz3cFK9rjhG4"
            + "hgpij/KwVEnkNsUbXcxlzUGlb8vBCWzXeUjuHjpDXuMYQV/iKBQVw//iA7aEPGMP9mkH0Z1QUF9D3fOhzjfwSjskxTK4upLmtX1j"
            + "ZQDy0hmg5HzPm0lJjwzZubvHpaPEeCdEuXFzg0YbxMcIWtgMsHrzAp+bVmVvqy2G/VE2HpsZr0TKcS1jZMz1UwDbXS4qWZkGBacB"
            + "SSLpUWu45t6cTp87/shSqNlTNcDHEGyvSVWAArcwMwIDAQABo1MwUTAdBgNVHQ4EFgQU+h5zUzR4bxEECqbkgAT1InVz4qwwHwYD"
            + "VR0jBBgwFoAU+h5zUzR4bxEECqbkgAT1InVz4qwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEATpX7Bu/+qEPb"
            + "aJnbppu3YSrE1J27Z44JcZrgfrcBrgOAmK/Q3oa90rGP8LbEZZWGoENtK4SN38XJMSqxxzirRUSqgzgg1blByx52I91lGqJRUy+M"
            + "9NZ3M5xOuFGNGpuFmLXEF5uexKgkFQvqJTKzlGe3hbVffM9pkJ5d5sM+bNhRnvAoo8IPJcFLT5+mNaUx91xeP8LBUHg0WwcfqE9x"
            + "IG1/Twt3GjGzUbqKmNrNQ+czKsDmIptdBQlwlDQ3Qu4iao6huFijdRKeOrEK2AA1i/MEA556zihGzzhooiSX3RRuZx7mTeb1x0rM"
            + "WUXEv9quECNEIuX/2NeExb3oK4Tm0A==";

    static final String TEST_CA_SUBJECT_CN = "win-trust-java test CA";

    private TestCertificates() {
    }
}
