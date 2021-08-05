# fork of JSch-0.1.55

See original [README](README)

[![GitHub release](https://img.shields.io/github/v/tag/mwiede/jsch.svg)](https://github.com/mwiede/jsch/releases/latest)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.mwiede/jsch/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.github.mwiede/jsch)
![Java CI with Maven](https://github.com/mwiede/jsch/workflows/Java%20CI%20with%20Maven/badge.svg)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=mwiede_jsch&metric=alert_status)](https://sonarcloud.io/dashboard?id=mwiede_jsch)

## Why should you use this library?

As I explained in a [blog post](http://www.matez.de/index.php/2020/06/22/the-future-of-jsch-without-ssh-rsa/) the main points are:
* OpenSSH will disable ssh-rsa in the future per default and you need a library which supports rsa-sha2-256 and rsa-sha2-512
* drop in replacement: just change dependency coordinates and you are good to go
* no active maintenance of [JSch at SourceForge](https://sourceforge.net/projects/jsch/)
* stay in sync with JDK features so there is no need for additional dependencies

## FAQ

* Is this fork 100% compatible with original Jsch, because the connection to my server does not work any more
  * for compatibility with openssh and security, the order of signure algorithms was changed. If you still want to use older or deprecated algorithms, you need to change the configuration. Examples see [#37](https://github.com/mwiede/jsch/issues/37), [#40](https://github.com/mwiede/jsch/issues/40)
* Is ssh-ed25519 supported?
  * This library is a Multi-Release-jar, which means, that you can only use certain features, when a more recent java version is used. In order to use ssh-ed25519, you must use at least Java 15

## Changes since fork:
* [0.1.64](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.64) Fixing [#55](https://github.com/mwiede/jsch/pull/55)
* [0.1.63](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.63) Fixing [#42](https://github.com/mwiede/jsch/issues/42)
* [0.1.62](https://github.com/mwiede/jsch/releases/tag/jsch-0.1.62) bugfixes and code cleanup
* 0.1.61
  * Add support for chacha20-poly1305@<!-- -->openssh.com, ssh-ed25519, ssh-ed448, curve448-sha512, diffie-hellman-group15-sha512 & diffie-hellman-group17-sha512. This makes use of the new EdDSA feature added in [Java 15's JEP 339](https://openjdk.java.net/jeps/339). [#17](https://github.com/mwiede/jsch/pull/17)
  * added integration test for public key authentication [#19](https://github.com/mwiede/jsch/pull/19)
* 0.1.60 
  * support for openssh-v1-private-key format [opensshFormat.md](opensshFormat.md).
  * Fix bug with AEAD ciphers when compression is used. [#15](https://github.com/mwiede/jsch/pull/15)
* 0.1.59 fixing issue from https://sourceforge.net/p/jsch/mailman/message/36872566/
* 0.1.58 support for more algorithms contributed by [@norrisjeremy](https://github.com/norrisjeremy) see [#4](https://github.com/mwiede/jsch/pull/4)
* 0.1.57 support for rsa-sha2-256 and rsa-sha2-512. [#1](https://github.com/mwiede/jsch/pull/1)
* 0.1.56 support for direct-streamlocal@<!-- -->openssh.com (see [SocketForwardingL.java](examples/SocketForwardingL.java))
