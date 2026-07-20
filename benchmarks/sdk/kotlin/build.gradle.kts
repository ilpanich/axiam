import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// AXIAM Kotlin SDK client benchmark (axiam.sdk-bench/v1 harness). See ../HARNESS-SPEC.md
// and TODO.md. Run: ./gradlew -q --console=plain run   (or: just sdk=kotlin sdk-bench)
plugins {
    kotlin("jvm") version "2.1.0"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    // The AXIAM Kotlin SDK. Resolved from the sibling axiam-kotlin-sdk checkout via the
    // includeBuild composite in settings.gradle.kts until the alpha package is published
    // to Maven Central. Swap to a plain version bump once it is (see TODO.md).
    implementation("io.github.ilpanich:axiam-sdk-kotlin:1.0.0-alpha13")
}

kotlin {
    // Matches the SDK's own target (JVM 17 bytecode); runs fine on a newer JDK too.
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

java {
    // Keep compileJava's target consistent with compileKotlin's (both 17) — Gradle
    // fails the build otherwise ("Inconsistent JVM-target compatibility") even though
    // this project has no Java sources, because the `application` plugin still wires
    // up a (source-less) compileJava task that defaults to the running JDK's release.
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

application {
    // Bench.kt has a top-level `fun main()` in package io.axiam.bench, so Kotlin
    // generates the facade class io.axiam.bench.BenchKt.
    mainClass.set("io.axiam.bench.BenchKt")
}

tasks.named<JavaExec>("run") {
    // Let the bench's own stdout JSON reach the caller uninterrupted.
    standardOutput = System.out
    errorOutput = System.err
}
