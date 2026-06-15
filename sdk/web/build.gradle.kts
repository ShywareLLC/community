// Shyware SDK — exposes DPIAHelpers library for Stack 6 DPIA consumer tests
plugins {
    kotlin("jvm") version "2.0.21"
    kotlin("plugin.serialization") version "2.0.21"
    `java-library`
}

group   = "com.sayists.shyware"
version = "0.4.0"

repositories { mavenCentral() }

dependencies {
    api("com.squareup.okhttp3:okhttp:4.12.0")
    api("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    api("org.json:json:20240303")  // JVM equivalent of Android's built-in org.json.JSONObject
    testImplementation(sourceSets.main.get().output)
    testImplementation(kotlin("test-junit"))
    testImplementation("junit:junit:4.13.2")
}

sourceSets {
    main {
        kotlin {
            // DPIAHelpers test utilities (package: dpia)
            srcDir("Sources/DPIAHelpers")
            // SDK client classes — srcDir must be the kotlin root so com/sayists/shyware/* resolves correctly
            // Excludes three Android-API-only files (PlayIntegrity, ReceiptStore, WriteOnlyPosture)
            srcDir("../android/src/main/kotlin")
            exclude(
                "com/sayists/shyware/PlayIntegrity.kt",
                "com/sayists/shyware/ReceiptStore.kt",
                "com/sayists/shyware/WriteOnlyPosture.kt",
            )
        }
    }
    test {
        kotlin {
            srcDir("tests/kotlin")
            srcDir("../android/src/main/kotlin")
            exclude(
                "com/sayists/shyware/PlayIntegrity.kt",
                "com/sayists/shyware/ReceiptStore.kt",
                "com/sayists/shyware/WriteOnlyPosture.kt",
            )
        }
    }
}

tasks.test {
    useJUnit()
    testLogging { events("passed", "skipped", "failed"); showStandardStreams = true }
}
