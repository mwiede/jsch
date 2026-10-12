# JSch Android support

This artifact adds Android JCA implementations without changing the main JSch JAR. Add `jsch` and `jsch-android` at the same version, then call `AndroidJSch.configure()` before opening a session.

The call selects platform Ed25519 or Ed448 signing only when one provider can sign with an imported key. It selects platform X25519 key exchange when the provider offers key agreement, key generation, and key import. Other algorithms keep JSch's existing BouncyCastle configuration. The Android XDH class also falls back to BouncyCastle for X448.

The Android test app is in `../android-test`. Build the main JAR with `./mvnw install`, build this artifact with `./mvnw -f jsch-android/pom.xml test package`, then put both JARs in `android-test/` before building its APKs.
