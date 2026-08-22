plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.sfmpas.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.sfmpas.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        viewBinding = true
    }

    androidResources {
        // The .tflite model MUST stay uncompressed in the APK: PadInferenceEngine
        // memory-maps it straight out of the asset directory, which only works on
        // a stored (not deflated) entry.
        noCompress += "tflite"
    }
}

// Kotlin's compiler options live at the project level, not inside `android { }`.
kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // --- fingerprint capture ---------------------------------------------
    implementation(libs.androidx.biometric)

    // --- TFLite model execution ------------------------------------------
    implementation(libs.tensorflow.lite)
    implementation(libs.tensorflow.lite.support)

    // --- backend communication -------------------------------------------
    implementation(libs.retrofit)
    implementation(libs.retrofit.converter.gson)

    // --- secure storage ---------------------------------------------------
    implementation(libs.androidx.security.crypto)

    // --- navigation between the four screens ------------------------------
    implementation(libs.androidx.navigation.fragment.ktx)
    implementation(libs.androidx.navigation.ui.ktx)
    implementation(libs.androidx.fragment.ktx)

    // --- transaction history ----------------------------------------------
    implementation(libs.androidx.recyclerview)
    implementation(libs.gson)

    // --- baseline ---------------------------------------------------------
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
