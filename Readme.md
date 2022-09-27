# Fork of JSch-0.1.55

See original [README](README)

[![GitHub release](https://img.shields.io/github/v/tag/mwiede/jsch.svg)](https://github.com/mwiede/jsch/releases/latest)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.mwiede/jsch/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.github.mwiede/jsch)
![Java CI with Maven](https://github.com/mwiede/jsch/workflows/Java%20CI%20with%20Maven/badge.svg)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=mwiede_jsch&metric=coverage)](https://sonarcloud.io/summary/overall?id=mwiede_jsch)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=mwiede_jsch&metric=bugs)](https://sonarcloud.io/summary/overall?id=mwiede_jsch)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=mwiede_jsch&metric=sqale_rating)](https://sonarcloud.io/summary/overall?id=mwiede_jsch)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=mwiede_jsch&metric=reliability_rating)](https://sonarcloud.io/summary/overall?id=mwiede_jsch)

## Why should you use this library?

As I explained in a [blog post](http://www.matez.de/index.php/2020/06/22/the-future-of-jsch-without-ssh-rsa/) the main points are:
* OpenSSH has disabled ssh-rsa in [release 8.8](https://www.openssh.com/txt/release-8.8) per default and you need a library which supports rsa-sha2-256 and rsa-sha2-512.
* Drop in replacement: just change dependency coordinates and you are good to go.
* No active maintenance of [JSch at SourceForge](https://sourceforge.net/projects/jsch/).
* Stay in sync with OpenJDK features so there is no need for additional dependencies.

## How to you use this library as a replacement for `com.jcraft:jsch`

Make sure, that you only have one jsch dependency on your classpath. For example you can check the output of `mvn dependency:tree`.

### by replacing a direct maven dependency

replace
```xml
<dependency>
    <groupId>com.jcraft</groupId>
    <artifactId>jsch</artifactId>
    <version>0.1.55</version>
</dependency>
```
with
```xml
<dependency>
  <groupId>com.github.mwiede</groupId>
  <artifactId>jsch</artifactId>
  <version>0.2.4</version>
</dependency>
```

### by replacing jsch as a transitive maven dependency
When you have an artifact `foo:bar`, which contains `com.jcraft:jsch` as a transitive dependency, you need to add `com.github.mwiede:jsch` as another dependency and exclude the jcraft one:
```xml
<dependency>
  <groupId>com.github.mwiede</groupId>
  <artifactId>jsch</artifactId>
  <version>0.2.4</version>
</dependency>
<dependency>
  <groupId>foo</groupId>
  <artifactId>bar</artifactId>
  <exclusions>
        <exclusion>  
          <groupId>com.jcraft</groupId>
          <artifactId>jsch</artifactId>
        </exclusion>
      </exclusions> 
</dependency>
```
## FAQ
### Are ssh-ed25519, ssh-ed448, curve25519-sha256, curve448-sha512 & chacha20-poly1305@<!-- -->openssh.com supported?
  * This library is a Multi-Release-jar, which means that you can only use certain features when a more recent Java version is used.
    * In order to use ssh-ed25519 & ssh-ed448, you must use at least Java 15 or add [Bouncy Castle](https://www.bouncycastle.org/java.html) (bcprov-jdk18on) to the classpath.
    * In order to use curve25519-sha256 & curve448-sha512, you must use at least Java 11 or add [Bouncy Castle](https://www.bouncycastle.org/java.html) (bcprov-jdk18on) to the classpath.
    * In order to use chacha20-poly1305@<!-- -->openssh.com, you must add [Bouncy Castle](https://www.bouncycastle.org/java.html) (bcprov-jdk18on) to the classpath.
  * As of the [0.1.66](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.66) release, these algorithms can now be used with older Java releases if [Bouncy Castle](https://www.bouncycastle.org/java.html) (bcprov-jdk18on) is added to the classpath.
    * As of the [0.1.72](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.72) release, chacha20-poly1305@<!-- -->openssh.com can only be used if [Bouncy Castle](https://www.bouncycastle.org/java.html) (bcprov-jdk18on) is added to the classpath.
### Why do ssh-rsa type keys not work with this JSch fork and my server?
  * As of the [0.2.0](https://github.com/mwiede/jsch/releases/tag/jsch-0.2.0) release, the RSA/SHA1 signature algorithm is disabled by default.
    * SHA1 is no longer considered secure by the general cryptographic community and this JSch fork strives to maintain secure choices for default algorithms that it will utilize.
    * This also follows the lead of the OpenSSH project in which they disabled RSA/SHA1 signatures by default as of [OpenSSH release 8.8](https://www.openssh.com/txt/release-8.8).
  * ssh-rsa type keys continue to function by default with the RSA/SHA256 (rsa-sha2-256) & RSA/SHA512 (rsa-sha2-512) signature algorithms defined by [RFC 8332](https://datatracker.ietf.org/doc/html/rfc8332).
  * If your server only supports RSA/SHA1 signatures and you require their use in your application, then you will need to manually reenable them by one of the following means (also see wiki page [Jsch-Configuration](https://github.com/mwiede/jsch/wiki/Jsch-Configuration)):
    * Globally by adding "ssh-rsa" to the `jsch.server_host_key` + `jsch.client_pubkey` properties.
    * Globally by executing something similar to `JSch.setConfig("server_host_key", JSch.getConfig("server_host_key") + ",ssh-rsa")` + `JSch.setConfig("PubkeyAcceptedAlgorithms", JSch.getConfig("PubkeyAcceptedAlgorithms") + ",ssh-rsa")`.
    * On a per-session basis by executing something similar to `session.setConfig("server_host_key", session.getConfig("server_host_key") + ",ssh-rsa")` + `session.setConfig("PubkeyAcceptedAlgorithms", session.getConfig("PubkeyAcceptedAlgorithms") + ",ssh-rsa")`.
    * Adding "ssh-rsa" to your OpenSSH type config file with the "HostKeyAlgorithms" + "PubkeyAcceptedAlgorithms" keywords & then utilizing the `OpenSSHConfig` class.
### Is this fork 100% compatible with original JSch, because the connection to my server does not work any more!
  * For compatibility with OpenSSH and improved security, the order of crypto algorithms was changed. If you still want to use older or deprecated algorithms, you need to change the configuration. Examples see [#37](https://github.com/mwiede/jsch/issues/37), [#40](https://github.com/mwiede/jsch/issues/40)
  * To make it easier to adjust the crypto algorithms, starting with [0.1.65](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.65) the following system properties can be set at your application's startup:
    * `jsch.kex`
      * analogous to `JSch.setConfig("kex", "...")`
    * `jsch.server_host_key`
      * analogous to `JSch.setConfig("server_host_key", "...")`
    * `jsch.prefer_known_host_key_types`
      * analogous to `JSch.setConfig("prefer_known_host_key_types", "...")`
    * `jsch.enable_server_sig_algs`
      * analogous to `JSch.setConfig("enable_server_sig_algs", "...")`
    * `jsch.cipher`
      * analogous to `JSch.setConfig("cipher.s2c", "...")` + `JSch.setConfig("cipher.c2s", "...")`
    * `jsch.mac`
      * analogous to `JSch.setConfig("mac.s2c", "...")` + `JSch.setConfig("mac.c2s", "...")`
    * `jsch.compression`
      * analogous to `JSch.setConfig("compression.s2c", "...")` + `JSch.setConfig("compression.c2s", "...")`
    * `jsch.lang`
      * analogous to `JSch.setConfig("lang.s2c", "...")` + `JSch.setConfig("lang.c2s", "...")`
    * `jsch.dhgex_min`
      * analogous to `JSch.setConfig("dhgex_min", "...")`
    * `jsch.dhgex_max`
      * analogous to `JSch.setConfig("dhgex_max", "...")`
    * `jsch.dhgex_preferred`
      * analogous to `JSch.setConfig("dhgex_preferred", "...")`
    * `jsch.compression_level`
      * analogous to `JSch.setConfig("compression_level", "...")`
    * `jsch.preferred_authentications`
      * analogous to `JSch.setConfig("PreferredAuthentications", "...")`
    * `jsch.client_pubkey`
      * analogous to `JSch.setConfig("PubkeyAcceptedAlgorithms", "...")`
    * `jsch.check_ciphers`
      * analogous to `JSch.setConfig("CheckCiphers", "...")`
    * `jsch.check_macs`
      * analogous to `JSch.setConfig("CheckMacs", "...")`
    * `jsch.check_kexes`
      * analogous to `JSch.setConfig("CheckKexes", "...")`
    * `jsch.check_signatures`
      * analogous to `JSch.setConfig("CheckSignatures", "...")`
    * `jsch.fingerprint_hash`
      * analogous to `JSch.setConfig("FingerprintHash", "...")`
    * `jsch.max_auth_tries`
      * analogous to `JSch.setConfig("MaxAuthTries", "...")`

## Changes since fork:
See [ChangeLog.md](ChangeLog.md)
