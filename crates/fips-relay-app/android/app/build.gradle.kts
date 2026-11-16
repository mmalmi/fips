plugins { id("com.android.application") }

val isolatedBench = providers.gradleProperty("isolatedBench")
    .map { it.toBooleanStrict() }.getOrElse(false)
val benchInstance = providers.gradleProperty("benchInstance").orNull
require(benchInstance == null || (isolatedBench && Regex("[a-z][a-z0-9]{0,23}").matches(benchInstance))) {
    "benchInstance requires isolatedBench and a lowercase letter followed by up to 23 lowercase letters or digits"
}
val benchPackage = if (isolatedBench) "org.fips.relaybench.acceptance" else "org.fips.relaybench"
val benchScheme = if (isolatedBench) "fipsbench-acceptance" else "fipsbench"

android {
    namespace = "org.fips.relaybench"
    compileSdk = 36
    ndkVersion = "28.2.13676358"
    defaultConfig {
        applicationId = benchPackage + (benchInstance?.let { ".$it" } ?: "")
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "0.1"
        ndk { abiFilters += "arm64-v8a" }
        manifestPlaceholders["benchLabel"] = if (isolatedBench) "FIPS Bench ${benchInstance ?: "Acceptance"}" else "FIPS Bench"
        manifestPlaceholders["benchScheme"] = benchScheme + (benchInstance?.let { "-$it" } ?: "")
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
    testImplementation("org.robolectric:robolectric:4.17")
    constraints {
        testImplementation("org.bouncycastle:bcprov-jdk18on:1.85")
        testImplementation("androidx.test:monitor:1.8.0")
        testImplementation("androidx.test.espresso:espresso-idling-resource:3.7.0")
    }
}
