# Fork of JSch-0.1.55

See original [README](README)

[![GitHub release](https://img.shields.io/github/v/tag/mwiede/jsch.svg)](https://github.com/mwiede/jsch/releases/latest)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.mwiede/jsch/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.github.mwiede/jsch)
![Java CI with Maven](https://github.com/mwiede/jsch/workflows/Java%20CI%20with%20Maven/badge.svg)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=mwiede_jsch&metric=alert_status)](https://sonarcloud.io/dashboard?id=mwiede_jsch)

## Why should you use this library?

As I explained in a [blog post](http://www.matez.de/index.php/2020/06/22/the-future-of-jsch-without-ssh-rsa/) the main points are:
* OpenSSH will disable ssh-rsa in the future per default and you need a library which supports rsa-sha2-256 and rsa-sha2-512.
* Drop in replacement: just change dependency coordinates and you are good to go.
* No active maintenance of [JSch at SourceForge](https://sourceforge.net/projects/jsch/).
* Stay in sync with OpenJDK features so there is no need for additional dependencies.

## FAQ

* Is this fork 100% compatible with original JSch, because the connection to my server does not work any more!
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
* Are ssh-ed25519, ssh-ed448, curve25519-sha256, curve448-sha512 & chacha20-poly1305@<!-- -->openssh.com supported?
  * This library is a Multi-Release-jar, which means that you can only use certain features when a more recent Java version is used.
    * In order to use ssh-ed25519 & ssh-ed448, you must use at least Java 15.
    * In order to use curve25519-sha256, curve448-sha512 & chacha20-poly1305@<!-- -->openssh.com, you must use at least Java 11.
  * As of the [0.1.66](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.66) release, these algorithms can now be used with older Java releases if [Bouncy Castle](https://www.bouncycastle.org/) (bcprov-jdk15on) is added to the classpath.

## Changes since fork:
* [0.1.66](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.66)
  * Added support for [RFC 8308](https://datatracker.ietf.org/doc/html/rfc8308) extension negotiation and server-sig-algs extension
    * This support is enabled by default, but can be controlled via the enable_server_sig_algs config option (or `jsch.enable_server_sig_algs` system property)
    * When enabled and a server-sig-algs message is received from the server, the algorithms included by the server and also present in the PubkeyAcceptedKeyTypes config option will be attempted first when using publickey authentication
    * Additionally if the server is detected as OpenSSH version 7.4, the rsa-sha2-256 & rsa-sha2-512 algorithms will be added to the received server-sig-algs as a workaround for [OpenSSH bug 2680](https://bugzilla.mindrot.org/show_bug.cgi?id=2680)
  * Added support for various algorithms supported by Tectia (ssh.com):
    * diffie-hellman-group14-sha224@<!-- -->ssh.com
    * diffie-hellman-group14-sha256@<!-- -->ssh.com
    * diffie-hellman-group15-sha256@<!-- -->ssh.com
    * diffie-hellman-group15-sha384@<!-- -->ssh.com
    * diffie-hellman-group16-sha384@<!-- -->ssh.com
    * diffie-hellman-group16-sha512@<!-- -->ssh.com
    * diffie-hellman-group18-sha512@<!-- -->ssh.com
    * diffie-hellman-group-exchange-sha224@<!-- -->ssh.com
    * diffie-hellman-group-exchange-sha384@<!-- -->ssh.com
    * diffie-hellman-group-exchange-sha512@<!-- -->ssh.com
    * hmac-sha224@<!-- -->ssh.com
    * hmac-sha256@<!-- -->ssh.com
    * hmac-sha256-2@<!-- -->ssh.com
    * hmac-sha384@<!-- -->ssh.com
    * hmac-sha512@<!-- -->ssh.com
    * ssh-rsa-sha224@<!-- -->ssh.com
    * ssh-rsa-sha256@<!-- -->ssh.com
    * ssh-rsa-sha384@<!-- -->ssh.com
    * ssh-rsa-sha512@<!-- -->ssh.com
  * Added support for SHA224 to FingerprintHash
  * Fixing [#52](https://github.com/mwiede/jsch/issues/52)
  * Deprecate `void setFilenameEncoding(String encoding)` in favor of `void setFilenameEncoding(Charset encoding)` in `ChannelSftp`
  * Added support for rsa-sha2-256 & rsa-rsa2-512 algorithms to `ChannelAgentForwarding`
  * Address [#65](https://github.com/mwiede/jsch/issues/65) by adding ssh-agent support derived from [jsch-agent-proxy](https://github.com/ymnk/jsch-agent-proxy)
    * See `examples/JSchWithAgentProxy.java` for simple example
    * ssh-agent support requires either [Java 16's JEP 380](https://openjdk.java.net/jeps/380) or the addition of [junixsocket](https://github.com/kohlschutter/junixsocket) to classpath
    * Pageant support is untested & requires the addition of [JNA](https://github.com/java-native-access/jna) to classpath
  * Added support for the following algorithms with older Java releases by using [Bouncy Castle](https://www.bouncycastle.org/):
    * ssh-ed25519
    * ssh-ed448
    * curve25519-sha256
    * curve25519-sha256@<!-- -->libssh.org
    * curve448-sha512
    * chacha20-poly1305@<!-- -->openssh.com
* [0.1.65](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.65)
  * Added system properties to allow manipulation of various crypto algorithms used by default
  * Integrated JZlib, allowing use of zlib@<!-- -->openssh.com & zlib compressions without the need to provide the JZlib jar-file
  * Modularized the jar-file for use with Java 9 or newer
  * Added runtime controls for the min/max/preferred sizes used for diffie-hellman-group-exchange-sha256 & diffie-hellman-group-exchange-sha1
  * Renamed PubkeyAcceptedKeyTypes config to PubkeyAcceptedAlgorithms to match recent changes in OpenSSH (PubkeyAcceptedKeyTypes is still accepted for backward compatibility)
  * Reduced number of algorithms that are runtime checked by default via CheckCiphers, CheckMacs, CheckKexes & CheckSignatures to improve runtime performance
  * Added config options dhgex_min, dhgex_max & dhgex_preferred to allow runtime manipulation of key size negotiation in diffie-hellman-group-exchange type Kex algorithms
    * Default values are:
    * dhgex_min = 2048
    * dhgex_max = 8192
    * dhgex_preferred = 3072
* [0.1.64](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.64) Fixing [#55](https://github.com/mwiede/jsch/pull/55)
* [0.1.63](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.63) Fixing [#42](https://github.com/mwiede/jsch/issues/42)
* [0.1.62](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.62) bugfixes and code cleanup
* [0.1.61](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.61)
  * Add support for chacha20-poly1305@<!-- -->openssh.com, ssh-ed25519, ssh-ed448, curve448-sha512, diffie-hellman-group15-sha512 & diffie-hellman-group17-sha512. This makes use of the new EdDSA feature added in [Java 15's JEP 339](https://openjdk.java.net/jeps/339). [#17](https://github.com/mwiede/jsch/pull/17)
  * added integration test for public key authentication [#19](https://github.com/mwiede/jsch/pull/19)
* [0.1.60](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.60)
  * support for openssh-v1-private-key format [opensshFormat.md](opensshFormat.md).
  * Fix bug with AEAD ciphers when compression is used. [#15](https://github.com/mwiede/jsch/pull/15)
* [0.1.59](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.59) fixing issue from https://sourceforge.net/p/jsch/mailman/message/36872566/
* [0.1.58](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.58) support for more algorithms contributed by [@norrisjeremy](https://github.com/norrisjeremy) see [#4](https://github.com/mwiede/jsch/pull/4)
* [0.1.57](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.57) support for rsa-sha2-256 and rsa-sha2-512. [#1](https://github.com/mwiede/jsch/pull/1)
* [0.1.56](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.56) support for direct-streamlocal@<!-- -->openssh.com (see [SocketForwardingL.java](examples/SocketForwardingL.java))
