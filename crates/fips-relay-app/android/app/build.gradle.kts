plugins { id("com.android.application") }

val isolatedBench = providers.gradleProperty("isolatedBench")
    .map { it.toBooleanStrict() }.getOrElse(false)

android {
    namespace = "org.fips.relaybench"
    compileSdk = 36
    ndkVersion = "28.2.13676358"
    defaultConfig {
        applicationId = if (isolatedBench) "org.fips.relaybench.acceptance" else "org.fips.relaybench"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "0.1"
        ndk { abiFilters += "arm64-v8a" }
        manifestPlaceholders["benchLabel"] = if (isolatedBench) "FIPS Bench Acceptance" else "FIPS Bench"
        manifestPlaceholders["benchScheme"] = if (isolatedBench) "fipsbench-acceptance" else "fipsbench"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions { unitTests.isIncludeAndroidResources = true }
    lint {
        abortOnError = true
        warningsAsErrors = true
        // This local phone prototype deliberately ships only the arm64 library.
        disable += "ChromeOsAbiSupport"
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.15")
    constraints {
        testImplementation("org.bouncycastle:bcprov-jdk18on:1.85")
        testImplementation("androidx.test:monitor:1.8.0")
        testImplementation("androidx.test.espresso:espresso-idling-resource:3.7.0")
    }
}
