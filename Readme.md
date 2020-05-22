# fork of jsch-1.55

See original [README](README)

[![GitHub release](https://img.shields.io/github/v/tag/mwiede/jsch.svg)](https://github.com/mwiede/jsch/releases/latest)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.mwiede/jsch/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.github.mwiede/jsch)

Changes:
* support for direct-streamlocal@openssh.com

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
