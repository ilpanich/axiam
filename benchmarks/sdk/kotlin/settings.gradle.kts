rootProject.name = "axiam-sdk-bench-kotlin"

// Build against the sibling axiam-kotlin-sdk checkout as a composite build so this
// bench compiles even before io.github.ilpanich:axiam-sdk-kotlin is published to
// Maven Central (mirrors the Java bench's local `mvn install` into ~/.m2 — see
// ../java/pom.xml — but Gradle's composite-build substitution needs no separate
// install step: the included build's output is used directly).
//
// Path is relative to this directory (benchmarks/sdk/kotlin), same depth as the
// Java bench's `../../../../axiam-java-sdk`: up to the repo root, then into the
// sibling `axiam-kotlin-sdk` checkout.
includeBuild("../../../../axiam-kotlin-sdk") {
    dependencySubstitution {
        substitute(module("io.github.ilpanich:axiam-sdk-kotlin")).using(project(":"))
    }
}
