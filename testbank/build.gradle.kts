plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

// Dummy "banking" app used ONLY for BANKVAULT acceptance tests. Never test against real bank apps.
android {
    namespace = "com.bankvault.testbank"
    compileSdk = 36
    defaultConfig {
        applicationId = "com.bankvault.testbank"
        minSdk = 34
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation(libs.kotlinx.coroutines.android)
}
