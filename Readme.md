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
* no active maintenance of jsch at sourceforge
* stay in sync with JDK features so there is no need for additional dependencies

## Changes since fork:
* 0.1.61
  * Add support for chacha20-poly1305@<!-- -->openssh.com, ssh-ed25519, ssh-ed448, curve448-sha512, diffie-hellman-group15-sha512 & diffie-hellman-group17-sha512. This makes use of the new EdDSA feature added in [Java 15's JEP 339](https://openjdk.java.net/jeps/339). [#17](https://github.com/mwiede/jsch/pull/17)
  * added integration test for public key authentication [#19](https://github.com/mwiede/jsch/pull/19)
* 0.1.60 
  * support for openssh-v1-private-key format [opensshFormat.md](opensshFormat.md).
  * Fix bug with AEAD ciphers when compression is used. [#15](https://github.com/mwiede/jsch/pull/15)
* 0.1.59 fixing issue from https://sourceforge.net/p/jsch/mailman/message/36872566/
* 0.1.58 support for more algorithms contributed by [@norrisjeremy](https://github.com/norrisjeremy) see [#4](https://github.com/mwiede/jsch/pull/4)
* 0.1.57 support for rsa-sha2-256 and rsa-sha2-512. [#1](https://github.com/mwiede/jsch/pull/1)
* 0.1.56 support for direct-streamlocal@<!-- -->openssh.com

Example: (see [SocketForwardingL.java](examples/SocketForwardingL.java))
```java
session.connect(30000);   // making a connection with timeout.

final int boundPort = session.setSocketForwardingL(null, 0, "/var/run/docker.sock", null, 1000);

URL myURL = new URL("http://localhost:" + boundPort + "/_ping");
HttpURLConnection myURLConnection = (HttpURLConnection) myURL.openConnection();
System.out.println("Docker Ping http response code (" + myURL + "): " + myURLConnection.getResponseCode());

session.disconnect();
```

or directly:

```java
final ChannelDirectStreamLocal channel = (ChannelDirectStreamLocal) session.openChannel("direct-streamlocal@openssh.com");
try {
    final OutputStream outputStream = channel.getOutputStream();
    final InputStream inputStream = channel.getInputStream();

    channel.setSocketPath("/var/run/docker.sock");
    channel.connect();

    String cmd = "GET /_ping HTTP/1.0\r\n\r\n";
    try (final PrintWriter printWriter = new PrintWriter(outputStream)) {
        printWriter.println(cmd);
        printWriter.flush();
    }
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
        for (String line; (line = reader.readLine()) != null; ) {
            System.out.println(line);
        }
    }
} catch (IOException exc) {
    exc.printStackTrace();
} finally {
    channel.disconnect();
}
```        
