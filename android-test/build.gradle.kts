plugins {
  id("com.android.application") version "8.13.0"
}

android {
  namespace = "com.jcraft.jsch.androidtest"
  compileSdk = 35

  defaultConfig {
    applicationId = "com.jcraft.jsch.androidtest"
    minSdk = 26
    targetSdk = 35
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
  }

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
  }
}

dependencies {
  implementation(files("jsch.jar", "jsch-android.jar"))
  androidTestImplementation("androidx.test:runner:1.7.0")
  androidTestImplementation("junit:junit:4.13.2")
  androidTestImplementation("org.bouncycastle:bcprov-jdk18on:1.85.2")
}
