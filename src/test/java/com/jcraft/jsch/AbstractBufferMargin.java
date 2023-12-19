package com.jcraft.jsch;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.github.valfirst.slf4jtest.LoggingEvent;
import com.github.valfirst.slf4jtest.TestLogger;
import com.github.valfirst.slf4jtest.TestLoggerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.input.BoundedInputStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
public abstract class AbstractBufferMargin {

  // Python can be slow for DH group 18
  private static final int timeout = 10000;
  private static final DigestUtils sha256sum = new DigestUtils(DigestUtils.getSha256Digest());
  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger =
      TestLoggerFactory.getTestLogger(AbstractBufferMargin.class);

  @TempDir
  public Path tmpDir;
  private Path in;
  private Path out;
  private String hash;
  private Slf4jLogConsumer sshdLogConsumer;

  @Container
  public GenericContainer<?> sshd;

  protected AbstractBufferMargin(int maxPktSize) {
    sshd = new GenericContainer<>(
        new ImageFromDockerfile().withFileFromClasspath("asyncsshd.py", "docker/asyncsshd.py")
            .withFileFromClasspath("ssh_host_ed448_key", "docker/ssh_host_ed448_key")
            .withFileFromClasspath("ssh_host_ed448_key.pub", "docker/ssh_host_ed448_key.pub")
            .withFileFromClasspath("ssh_host_rsa_key", "docker/ssh_host_rsa_key")
            .withFileFromClasspath("ssh_host_rsa_key.pub", "docker/ssh_host_rsa_key.pub")
            .withFileFromClasspath("ssh_host_ecdsa256_key", "docker/ssh_host_ecdsa256_key")
            .withFileFromClasspath("ssh_host_ecdsa256_key.pub", "docker/ssh_host_ecdsa256_key.pub")
            .withFileFromClasspath("ssh_host_ecdsa384_key", "docker/ssh_host_ecdsa384_key")
            .withFileFromClasspath("ssh_host_ecdsa384_key.pub", "docker/ssh_host_ecdsa384_key.pub")
            .withFileFromClasspath("ssh_host_ecdsa521_key", "docker/ssh_host_ecdsa521_key")
            .withFileFromClasspath("ssh_host_ecdsa521_key.pub", "docker/ssh_host_ecdsa521_key.pub")
            .withFileFromClasspath("ssh_host_ed25519_key", "docker/ssh_host_ed25519_key")
            .withFileFromClasspath("ssh_host_ed25519_key.pub", "docker/ssh_host_ed25519_key.pub")
            .withFileFromClasspath("ssh_host_dsa_key", "docker/ssh_host_dsa_key")
            .withFileFromClasspath("ssh_host_dsa_key.pub", "docker/ssh_host_dsa_key.pub")
            .withFileFromClasspath("authorized_keys", "docker/authorized_keys")
            .withFileFromClasspath("Dockerfile", "docker/Dockerfile.asyncssh")
            .withBuildArg("MAX_PKTSIZE", Integer.toString(maxPktSize)))
        .withExposedPorts(22);
  }

  @BeforeAll
  public static void beforeAll() {
    JSch.setLogger(new Slf4jLogger());
  }

  @BeforeEach
  public void beforeEach() throws IOException {
    if (sshdLogConsumer == null) {
      sshdLogConsumer = new Slf4jLogConsumer(sshdLogger);
      sshd.followOutput(sshdLogConsumer);
    }

    in = tmpDir.resolve("in");
    out = tmpDir.resolve("out");
    Files.createFile(in);
    try (OutputStream os = Files.newOutputStream(in)) {
      byte[] data = new byte[1024];
      for (int i = 0; i < 1024 * 100; i += 1024) {
        new Random().nextBytes(data);
        os.write(data);
      }
    }
    hash = sha256sum.digestAsHex(in);

    jschLogger.clearAll();
    sshdLogger.clearAll();
  }

  @AfterAll
  public static void afterAll() {
    JSch.setLogger(null);
    jschLogger.clearAll();
    sshdLogger.clearAll();
  }

  protected void doTestSftp(String cipher, String mac, String compression) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("cipher.s2c", cipher);
    session.setConfig("cipher.c2s", cipher);
    session.setConfig("mac.s2c", mac);
    session.setConfig("mac.c2s", mac);
    session.setConfig("compression.s2c", compression);
    session.setConfig("compression.c2s", compression);
    doSftp(session, true);
  }

  protected void doTestScp(String cipher, String mac, String compression) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("cipher.s2c", cipher);
    session.setConfig("cipher.c2s", cipher);
    session.setConfig("mac.s2c", mac);
    session.setConfig("mac.c2s", mac);
    session.setConfig("compression.s2c", compression);
    session.setConfig("compression.c2s", compression);
    doScp(session, true);
  }

  private JSch createRSAIdentity() throws Exception {
    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_rsa_key.pub"));
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_rsa"), getResourceFile("docker/id_rsa.pub"), null);
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private HostKey readHostKey(String fileName) throws Exception {
    List<String> lines = Files.readAllLines(Paths.get(fileName), UTF_8);
    String[] split = lines.get(0).split("\\s+");
    String hostname =
        String.format(Locale.ROOT, "[%s]:%d", sshd.getHost(), sshd.getFirstMappedPort());
    return new HostKey(hostname, Base64.getDecoder().decode(split[1]));
  }

  private Session createSession(JSch ssh) throws Exception {
    Session session = ssh.getSession("root", sshd.getHost(), sshd.getFirstMappedPort());
    session.setConfig("StrictHostKeyChecking", "yes");
    session.setConfig("PreferredAuthentications", "publickey");
    return session;
  }

  private void doSftp(Session session, boolean debugException) throws Exception {
    try {
      session.setTimeout(timeout);
      session.connect();
      ChannelSftp sftp = (ChannelSftp) session.openChannel("sftp");
      sftp.connect(timeout);
      sftp.put(in.toString(), "/root/test");
      sftp.get("/root/test", out.toString());
      sftp.disconnect();
      session.disconnect();
    } catch (Exception e) {
      if (debugException) {
        printInfo();
      }
      throw e;
    }

    assertEquals(1024L * 100L, Files.size(out));
    assertEquals(hash, sha256sum.digestAsHex(out));
  }

  private void doScp(Session session, boolean debugException) throws Exception {
    try {
      session.setTimeout(timeout);
      session.connect();
      ChannelExec scp;

      scp = (ChannelExec) session.openChannel("exec");
      try (InputStream is = scp.getInputStream()) {
        try (OutputStream os = scp.getOutputStream()) {
          scp.setCommand("scp -t /root/test");
          scp.connect(timeout);
          checkAck(is);
          String cmd = "C0644 102400 test\n";
          os.write(cmd.getBytes(UTF_8));
          os.flush();
          checkAck(is);
          Files.copy(in, os);
          os.flush();
          sendAck(os);
          checkAck(is);
        }
      }
      while (scp.isConnected()) {
        Thread.sleep(100L);
      }

      scp = (ChannelExec) session.openChannel("exec");
      try (OutputStream os = scp.getOutputStream()) {
        try (InputStream is = scp.getInputStream()) {
          scp.setCommand("scp -f /root/test");
          scp.connect(timeout);
          sendAck(os);
          int c = checkAck(is);
          if (c == 'C') {
            byte[] buf = new byte[17];
            is.read(buf, 0, 17);
            sendAck(os);
            Files.copy(new BoundedInputStream(is, 100L * 1024L), out);
            checkAck(is);
            sendAck(os);
          }
        }
      }
      while (scp.isConnected()) {
        Thread.sleep(100L);
      }

      session.disconnect();
    } catch (Exception e) {
      if (debugException) {
        printInfo();
      }
      throw e;
    }

    assertEquals(1024L * 100L, Files.size(out));
    assertEquals(hash, sha256sum.digestAsHex(out));
  }

  private static int checkAck(InputStream is) throws IOException {
    int b = is.read();
    if (b == 0) {
      return b;
    } else if (b == -1) {
      throw new IOException("no response");
    }

    StringBuilder sb = new StringBuilder();
    if (b == 1 || b == 2) {
      int c = is.read();
      while (c > 0 && c != '\n') {
        sb.append((char) c);
        c = is.read();
      }
    }

    switch (b) {
      case 1:
        throw new IOException("error: " + sb);
      case 2:
        throw new IOException("fatal error: " + sb);
      default:
        return b;
    }
  }

  private static void sendAck(OutputStream os) throws IOException {
    byte[] ack = new byte[1];
    ack[0] = 0;
    os.write(ack);
    os.flush();
  }

  private void printInfo() {
    jschLogger.getAllLoggingEvents().stream().map(LoggingEvent::getFormattedMessage)
        .forEach(System.out::println);
    sshdLogger.getAllLoggingEvents().stream().map(LoggingEvent::getFormattedMessage)
        .forEach(System.out::println);
    System.out.println("");
    System.out.println("");
    System.out.println("");
  }

  private String getResourceFile(String fileName) {
    return ResourceUtil.getResourceFile(getClass(), fileName);
  }
}
