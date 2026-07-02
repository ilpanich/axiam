# axiam-sdk (Java)

Official Java client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

## Package identity

- **Maven coordinates:** `io.axiam:axiam-sdk`
- **GroupId:** `io.axiam`
- **ArtifactId:** `axiam-sdk`
- **Registry:** Maven Central _(reserved, not yet published)_
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1-§10.

See [`../CONTRACT.md`](../CONTRACT.md) for the full cross-language behavioral contract.

## Getting started

### Maven

```xml
<dependency>
  <groupId>io.axiam</groupId>
  <artifactId>axiam-sdk</artifactId>
  <version>0.1.0</version>
</dependency>
```

Consumers depending on multiple AXIAM artifacts (e.g. `axiam-sdk` alongside a
future companion module) should import the BOM instead of pinning individual
versions:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>io.axiam</groupId>
      <artifactId>axiam-bom</artifactId>
      <version>0.1.0</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
```

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("io.axiam:axiam-sdk:0.1.0")
}
```

Or via the BOM:

```kotlin
dependencies {
    implementation(platform("io.axiam:axiam-bom:0.1.0"))
    implementation("io.axiam:axiam-sdk")
}
```

### Quick start

`tenantId` is a **required, positional** argument to `AxiamClient.builder(...)`
— AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5); a
blank value throws `AuthError` at construction time. `AxiamClient` is
`AutoCloseable`, so always construct it with try-with-resources to release
its underlying OkHttp connection pool/dispatcher:

```java
try (AxiamClient client = AxiamClient.builder("https://axiam.example.com", "acme-tenant").build()) {
    LoginResult result = client.login("user@example.com", "password");
    if (result.mfaRequired()) {
        result = client.verifyMfa(result.challengeToken(), "123456");
    }
    boolean allowed = client.can("read", "documents/123");
}
```

See [`examples/`](examples/) for runnable per-capability examples covering
login+MFA, REST authorization, gRPC `CheckAccess`, the AMQP consumer, and a
complete Spring Boot 3.x application wiring `AxiamAuthenticationFilter`
explicitly in a `SecurityFilterChain` bean.

## Status

Phase 20 (Java SDK) implementation.
