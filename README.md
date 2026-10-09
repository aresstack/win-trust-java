# win-trust-java

[![Maven Central](https://img.shields.io/maven-central/v/com.aresstack/win-trust-java.svg)](https://central.sonatype.com/artifact/com.aresstack/win-trust-java)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`win-trust-java` is a lightweight Java 8 library that builds an `SSLSocketFactory` (plus the
matching `SSLContext` and `X509TrustManager`) whose trust anchors come from **the JVM's `cacerts`
and the Windows certificate stores** — including the Intermediate Certification Authorities store
that Java's own `SunMSCAPI` provider cannot read.

It is the TLS-trust companion of [`win-proxy-java`](https://github.com/aresstack/win-proxy-java):
that library answers *how* an application reaches the network behind a managed Windows proxy,
this one answers *which certificates* the application trusts once it gets there. The two concerns
are deliberately independent and have no dependency on each other.

## Installation

```xml
<dependency>
  <groupId>com.aresstack</groupId>
  <artifactId>win-trust-java</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle:

```groovy
implementation 'com.aresstack:win-trust-java:0.1.0'
```

No transitive dependencies. Java 8 or newer.

## Why this library exists

Corporate workstations frequently sit behind a TLS-intercepting proxy. The proxy terminates TLS
and re-signs every response with a private CA. That CA is installed in the Windows certificate
store, so browsers, `curl` and .NET work — but the JVM only knows its bundled `cacerts`, so every
HTTPS request from Java fails during the handshake with

```text
PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException:
unable to find valid certification path to requested target
```

even though proxy discovery and resolution succeeded. Two Windows details make this worse than
"just add the root to `cacerts`":

1. **`SunMSCAPI` only exposes `Windows-ROOT` and `Windows-MY`.** The Windows *Intermediate
   Certification Authorities* store is invisible to Java.
2. **Intercepting proxies often omit the intermediate certificate from the handshake.**
   Windows/SChannel silently completes the chain from the intermediate store; Java's PKIX
   validator only has the server-sent certificates plus its anchors, so path building fails
   even when the corporate root *is* trusted via `Windows-ROOT`.

`win-trust-java` closes that gap by exporting the Root **and** Intermediate CA stores (machine and
user scope). Root-store certificates become additional trust anchors; Intermediate-store
certificates are handed to Java's PKIX path builder as chain-building material only, so the
missing intermediate can be filled in exactly as SChannel does. Nothing is trusted that Windows
does not trust: the Intermediate store is a cache Windows fills from every chain it sees, so its
entries are never promoted to anchors — an intermediate whose root is absent or distrusted stays
untrusted.

## Trust sources

`CertificateTrustConfiguration` selects any combination of three additive sources. A server chain
is accepted when **any** enabled source validates it; each source is a regular PKIX trust manager.

| Switch | Source | Needs | Notes |
| --- | --- | --- | --- |
| `useJvmDefault` | JVM default truststore (`cacerts` or `javax.net.ssl.trustStore`) | nothing | Plain JVM behaviour. |
| `useWindowsRoot` | `Windows-ROOT` keystore via `SunMSCAPI` | Windows | Trusted Root CAs only, in-process, no external process. |
| `useWindowsCaStores` | `Cert:\LocalMachine\Root`, `Cert:\CurrentUser\Root` as **anchors**; `Cert:\LocalMachine\CA`, `Cert:\CurrentUser\CA` as **path-building material** | Windows, `powershell.exe` | The only way to get the **Intermediate** store; also picks up GPO/enterprise-pushed CAs. Built with `PKIXBuilderParameters` + a `CertStore` of the intermediates. |

`CertificateTrustConfiguration.defaults()` enables all three — the combination that makes
intercepting proxies work out of the box. `CertificateTrustConfiguration.jvmDefaultOnly()` never
touches Windows. Individual sources are switched off with the builder:

```java
CertificateTrustConfiguration trust = CertificateTrustConfiguration.builder()
        .useWindowsCaStores(false)   // never spawn PowerShell
        .build();
```

On non-Windows platforms the two Windows sources simply contribute nothing (reported in the
diagnostics, no error, no process started).

## Quick start

```java
import com.aresstack.wintrust.CertificateTrustConfiguration;
import com.aresstack.wintrust.SystemTrustSslSocketFactory;

import javax.net.ssl.HttpsURLConnection;
import java.net.URL;

public final class TrustExample {
    public static void main(String[] args) throws Exception {
        SystemTrustSslSocketFactory.Result trust =
                SystemTrustSslSocketFactory.build(CertificateTrustConfiguration.defaults());

        HttpsURLConnection connection =
                (HttpsURLConnection) new URL("https://repo.maven.apache.org/maven2/").openConnection();
        connection.setSSLSocketFactory(trust.getSocketFactory());
        System.out.println(connection.getResponseCode());
    }
}
```

`build(...)` caches the result per configuration, because exporting the Windows stores spawns
PowerShell and takes a few seconds. Use `create(...)` for a fresh, uncached build (for example
after a new CA was rolled out) or `clearCache()` to drop all cached results.

### OkHttp, Apache HttpClient, …

Clients that want the trust manager next to the socket factory get it from the same result:

```java
SystemTrustSslSocketFactory.Result trust = SystemTrustSslSocketFactory.build(null); // null = defaults()

OkHttpClient client = new OkHttpClient.Builder()
        .sslSocketFactory(trust.getSocketFactory(), trust.getTrustManager())
        .build();
```

`getSslContext()` returns the underlying `SSLContext` for APIs that take one.

### Combining with win-proxy-java

```java
ProxyResult proxy = new WindowsProxyResolver().resolve(url);          // win-proxy-java: how to get there
SystemTrustSslSocketFactory.Result trust =
        SystemTrustSslSocketFactory.build(CertificateTrustConfiguration.defaults()); // win-trust-java: whom to trust

HttpsURLConnection connection = (HttpsURLConnection) new URL(url)
        .openConnection(proxy.toJavaProxyOrNoProxy());
connection.setSSLSocketFactory(trust.getSocketFactory());
```

## Diagnostics instead of silent failure

Nothing is swallowed. The `Result` tells you exactly which sources contributed:

```java
SystemTrustSslSocketFactory.Result trust = SystemTrustSslSocketFactory.build(null);

trust.isJvmDefaultTrusted();                 // true
trust.isWindowsRootTrusted();                // true on Windows, false elsewhere
trust.isWindowsCaStoresTrusted();            // true when the PowerShell export yielded root anchors
trust.getWindowsRootAnchorCount();           // e.g. 410 (Root stores → trust anchors)
trust.getWindowsIntermediateCount();         // e.g. 164 (Intermediate stores → path building only)
trust.getWindowsExportedCertificateCount();  // 574 = both together
trust.isFallbackToJvmDefault();              // true only when NO source produced a trust manager
trust.getDiagnostics();                      // ["JVM default truststore (cacerts) loaded.",
                                             //  "Windows-ROOT store loaded.",
                                             //  "Windows Root/Intermediate CA stores loaded 410 root anchor(s) and 164 intermediate certificate(s)."]
```

A connection test in an application can therefore distinguish "the proxy is wrong" from "the
intermediate CA is missing" from "PowerShell is blocked on this machine" — the diagnostics name
the cause, for example
`Windows Root/Intermediate CA export: Windows certificate export failed: Cannot run program "powershell.exe" …`.

`WindowsCertificateStores.loadRootAndIntermediateCertificates()` is public as well, for callers
that want the raw `X509Certificate` lists (`getRootCertificates()` for anchors,
`getIntermediateCertificates()` for chain building, e.g. to feed their own `PKIXBuilderParameters`).

## Hardened machines: inline PowerShell, no temporary files

The Windows store export runs as **one inline `powershell.exe -NoProfile -NonInteractive
-ExecutionPolicy Bypass -Command …` one-liner** that prints one Base64-encoded DER certificate
per line, prefixed with the store kind (`ROOT ` or `CA `):

```powershell
$ErrorActionPreference = 'SilentlyContinue'; foreach ($store in @('Cert:\LocalMachine\Root','Cert:\CurrentUser\Root')) { Get-ChildItem -Path $store | ForEach-Object { 'ROOT ' + [Convert]::ToBase64String($_.RawData) } }; foreach ($store in @('Cert:\LocalMachine\CA','Cert:\CurrentUser\CA')) { Get-ChildItem -Path $store | ForEach-Object { 'CA ' + [Convert]::ToBase64String($_.RawData) } }
```

It never writes a `.ps1` to `%TEMP%`, so it keeps working where GPO execution policy or
AppLocker block unsigned script files — the same hardening rule `win-proxy-java` applies to PAC
URL discovery. stdout and stderr are drained concurrently (no pipe-buffer deadlock on large
stores), the process is bounded by a timeout (`WindowsCertificateStores.DEFAULT_TIMEOUT_SECONDS`,
25 s; an overload accepts a custom value) and is killed when it exceeds it.

If PowerShell itself is locked down, `useWindowsRoot` still works in-process through `SunMSCAPI`
— you lose only the intermediate store, and the diagnostics say so.

## Main public types

| Type | Responsibility |
| --- | --- |
| `CertificateTrustConfiguration` | Immutable selection of trust sources (`defaults()`, `jvmDefaultOnly()`, `builder()`). |
| `SystemTrustSslSocketFactory` | Builds (and caches) the combined `SSLSocketFactory` / `SSLContext` / `X509TrustManager`. |
| `SystemTrustSslSocketFactory.Result` | The factory plus diagnostics: which sources loaded, how many certificates, what failed. |
| `WindowsCertificateStores` | Exports the Windows Root/Intermediate CA stores via inline PowerShell. |
| `WindowsCertificateStores.Result` | The exported certificates (roots and intermediates separately) plus an optional error message. |

## Runtime requirements

- Java 8 or newer.
- Windows for the two Windows sources (`SunMSCAPI` ships with every Windows JDK).
- `powershell.exe` (Windows PowerShell 5.1, present on every supported Windows) only for
  `useWindowsCaStores`.

## Building from source

The published **artifact targets Java 8** (`maven.compiler.source/target = 1.8`).

- **Maven Wrapper** (used by CI and the release) runs on **JDK 8** with the Maven version pinned
  in `.mvn/wrapper/maven-wrapper.properties` (3.9.16):
  ```bash
  ./mvnw -B clean verify -Dgpg.skip=true   # tests + sources jar + javadoc jar
  ```
- **Gradle wrapper**, pinned to Gradle 8.14.3 so it still runs on JDK 8:
  ```bash
  ./gradlew test
  ```

Two opt-in, environment-touching tests exist for Windows machines:

```bash
./mvnw verify -Dwintrust.diagnostics=true   # prints which source loaded what; never fails
./mvnw verify -Dwintrust.integration=true   # asserts the real inline PowerShell export works
```

CI runs the unit tests on Linux and the real export on a Windows runner for every push.

## Releasing

Releases are published to Maven Central by
[`.github/workflows/release.yml`](.github/workflows/release.yml) whenever a `v*` tag is pushed,
or manually via *Run workflow* (`workflow_dispatch`, which tags the released version itself).
It runs `./mvnw -B clean deploy` on JDK 8 with the `central-publishing-maven-plugin`, signed with
GPG; credentials come from the `CENTRAL_USERNAME`, `CENTRAL_PASSWORD`, `GPG_PRIVATE_KEY` and
`GPG_PASSPHRASE` secrets. The Maven Wrapper matters here: the runner's preinstalled Maven 3.10
leaves a `maven-metadata-local.xml` in the staging bundle that Central rejects. `release.ps1`
builds locally with the wrapper, creates the annotated tag from the version in `pom.xml` and
pushes it.

## License

[MIT](LICENSE)
