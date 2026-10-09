package com.aresstack.wintrust;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

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

    /**
     * A three-level chain generated for the tests (valid until 2056):
     * {@code CN=win-trust-java test root} signs {@code CN=win-trust-java test intermediate}
     * (CA:TRUE, pathlen 0), which signs the TLS server leaf {@code CN=proxy.example.test}
     * (keyUsage digitalSignature+keyEncipherment, extendedKeyUsage serverAuth).
     * The root is unrelated to {@link #TEST_CA_BASE64}.
     */
    static final String ROOT_BASE64 =
            "MIIDYTCCAkmgAwIBAgIUP3dzyyCos70QbfdeWdFKoEdvEd0wDQYJKoZIhvcNAQELBQAwNzEhMB8GA1UEAwwYd2luLXRydXN0LWph"
            + "dmEgdGVzdCByb290MRIwEAYDVQQKDAlBcmVzU3RhY2swIBcNMjYxMDA5MjIwMzAyWhgPMjA1NjEwMDEyMjAzMDJaMDcxITAfBgNV"
            + "BAMMGHdpbi10cnVzdC1qYXZhIHRlc3Qgcm9vdDESMBAGA1UECgwJQXJlc1N0YWNrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB"
            + "CgKCAQEAwbfIQavKcCLFFTFNCD+jDnanjcP26EnoqRfeajEaNz/Wnl5gll+jwGhfZZNcYSdntX9yhZ0lmSk7kniOrV6OI++kD4bK"
            + "UTC9o7k8a7f6QH0xJ5QV8hXU2BGOJwHJb3hR8JWKgrOxRjuNOmS+Zgyq6sY1DxFnCSm2eFw1j3rAuBZMD615kTJVUZ2ksmq878+y"
            + "CvnNwe/6P/N5VONgZOjsgJq7iNfbslPC2LYU7Bc+FJvO5k6IGwjhYuVyn3RsHZRzCXGTr9KBv5UQb1F5wNV1oOVJp5DMtXYPBP1o"
            + "xfs50jtHUnb6eD9beINyKcExuCZllm7uA7jOcp6qtXWmfUbV+QIDAQABo2MwYTAdBgNVHQ4EFgQUFS6yFBTS0Ae7qa3M3+Gl9JJx"
            + "syAwHwYDVR0jBBgwFoAUFS6yFBTS0Ae7qa3M3+Gl9JJxsyAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZI"
            + "hvcNAQELBQADggEBAK7zCjEL+OLGfmTSbCHiplvlkM+f1QfmuqpXKQDypGsoY/fg6eipYcKafbWYv1ZJO1Pbx2C8h19W6tLgoVVw"
            + "Wi1+GhVcYQtD3Hmeviw/4ZsW4OtuLFFCxYQxYoiIpNdxcST+9hf2XNk2dLpZKzR8Sz9gaZMAxCV6PzclJDj//HGBG/TB3ghExUr4"
            + "v6MlLFxVTsu6oZ5+vnBDBTFDPgUdSRoCUDuB/qgQRRzj0e+RuaKi3nhb2mMr0M2iIPhc9mWWV83E9elCf2omgmuDJOQ3oHZUaG3e"
            + "kF7ROGPj+NVVZ9U2itv91V1YcaoY1Bb9wFnXyONhkhMhDN8t+OD2eg3lNGk=";

    static final String INTERMEDIATE_BASE64 =
            "MIIDbDCCAlSgAwIBAgIUcoT7/QBSWGtEhCAGexx9vjz8AeYwDQYJKoZIhvcNAQELBQAwNzEhMB8GA1UEAwwYd2luLXRydXN0LWph"
            + "dmEgdGVzdCByb290MRIwEAYDVQQKDAlBcmVzU3RhY2swIBcNMjYxMDA5MjIwMzAyWhgPMjA1NjA4MTIyMjAzMDJaMD8xKTAnBgNV"
            + "BAMMIHdpbi10cnVzdC1qYXZhIHRlc3QgaW50ZXJtZWRpYXRlMRIwEAYDVQQKDAlBcmVzU3RhY2swggEiMA0GCSqGSIb3DQEBAQUA"
            + "A4IBDwAwggEKAoIBAQDpqLAlHu8vrATMM9nf54syWjwLO21aJIgisOssL/8MKufYhXeXYybrewqmVezpcVp8T+rbEA/qttWeCWrj"
            + "N35OiQxJy9J55E1afV1p1IvlU6kqCObF0ACsu4Ru+w/3qSpHPl6gDt6nVDWaDB07QooCurNfmFyf9ed2IKD2T97OjVmJv7GfEIPg"
            + "MtvHAVAntHo17kmmIP3EU2SvrUY1m6FLf/oB0L72ljGR32Z1fG2N7OSE93lVp0w37UqmH5CH5CxfCSRS+q9D8mkOC9wT+YD15Jb/"
            + "8qDwdhFexREnj+PuGIddBM5ZVcMKaMZqkux5IPWfVw+KLIRp/oSGMbw4x18fAgMBAAGjZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQAw"
            + "DgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQSuDIV2wy2hCKHuLfWV6PNamFYIzAfBgNVHSMEGDAWgBQVLrIUFNLQB7uprczf4aX0"
            + "knGzIDANBgkqhkiG9w0BAQsFAAOCAQEAlXyIjzZcKKwrPz77/i7QS3Yi/yIpv/8R6Lfr2+Nd+vm025FuZLQmHNKV77EzPKjQYLp8"
            + "LUEhg80Zwj9jxxBWO7/m0X3+17Ey7YSC778SVtrscxJrSonM5SB6MGjyw9mZ9nvJ9Bth1iyDYPuLpPziHJJVGoeQzZaXvmjot9Ph"
            + "DdK+oJLxFFxTf0+FKQLyBkmvq8Fu/s8vAbGgMXBkuE3ndcU2CleRK8yMM9E1aBOw7GVT7o8HkEV6nDG3h2LZd0GQU2rEB8+7xQCo"
            + "jiiU1IKmFVWFtpagKNq/7ZQOy0IReA9x3Woank7EJ5uQv+bj75u0jCs1LgOz+sVARpMIcyJ7cA==";

    static final String LEAF_BASE64 =
            "MIIDkzCCAnugAwIBAgIUAhmXxu8OKJjWp6pa5tcmgMqraOQwDQYJKoZIhvcNAQELBQAwPzEpMCcGA1UEAwwgd2luLXRydXN0LWph"
            + "dmEgdGVzdCBpbnRlcm1lZGlhdGUxEjAQBgNVBAoMCUFyZXNTdGFjazAgFw0yNjEwMDkyMjAzMDJaGA8yMDU2MDYyMzIyMDMwMlow"
            + "MTEbMBkGA1UEAwwScHJveHkuZXhhbXBsZS50ZXN0MRIwEAYDVQQKDAlBcmVzU3RhY2swggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw"
            + "ggEKAoIBAQC47obQx3dRAuG2IrrnCP46cnscnOcsFgaNddnpI4lNoLksHIKYBBck+z7AzVHFE/xjOfoFkEC10El+5xu7TDGuZ3HB"
            + "Yd2qeSR2rn4Y7ReGinyjDAaw3hG1o4/XantLwD7Ug7dlLTeYGfkDEoyLD6l+GE+w2AR9+Vw8YKGZpp9b0y2C2325iF6aFV29+Hiy"
            + "f4Aeo+tcC3AKeCbs7lGMktXxTQv4p0EYyokLUrw6o4k9YjqH+3qGMa7N3n0tWyk+JaAp3C9QYVyo+QWvGuNuuVjDJFHVc3JQjMrg"
            + "DAEpRG1k7tAx7jMk2Flhg9Fwtb8SNbsRxL/zyXFXjGfnRRJBqoArAgMBAAGjgZIwgY8wCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMC"
            + "BaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0RBBYwFIIScHJveHkuZXhhbXBsZS50ZXN0MB0GA1UdDgQWBBSpjXgqIxKWOQN7"
            + "30ZnfJCt1V7JgDAfBgNVHSMEGDAWgBQSuDIV2wy2hCKHuLfWV6PNamFYIzANBgkqhkiG9w0BAQsFAAOCAQEAi1EHKL8nFNNt3Dq3"
            + "jH574YTXieMV/07g5JHaANxrhveBKMomlwqyj2VPGvz+9/smhUuiPegWr6TpO5enBqgMUcXEQlJGnB+Z7465lTrP+M+WObk0P7xr"
            + "U8GAxUsnHWqZsyZu9dDpuaZXrLpoxjMHybH0THBmbZEk0kluEgDMK3VH25OoYms6wbgGU9TV9FFqxPVGAlOfyEMQ94lyE23szg+6"
            + "RZOB0qPWmW41iHdnTbT7XUlWgiN1KK+FmuQC9MWI3T4lRX2aLC0xgyI4nOUjfUBJKkyZNF/Tb+lNdNk4xSRGSjdLmUVEC2dlcdKS"
            + "eRMUpPjGW0ig63oDOGlf29BXmQ==";

    static X509Certificate decode(String base64) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(Base64.getMimeDecoder().decode(base64)));
        } catch (CertificateException ex) {
            throw new IllegalStateException("Test certificate is not parseable", ex);
        }
    }

    private TestCertificates() {
    }
}
