package com.jcraft.jsch;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.valfirst.slf4jtest.LoggingEvent;
import com.github.valfirst.slf4jtest.TestLogger;
import com.github.valfirst.slf4jtest.TestLoggerFactory;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Runs ProxyJump against a real sshd. The container is both the hop, reached through its mapped
 * port, and the target, which the hop reaches as {@code 127.0.0.1:22} inside the container.
 */
@Testcontainers
class ProxyJumpIT {

  private static final int TIMEOUT = 5000;
  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger = TestLoggerFactory.getTestLogger(ProxyJumpIT.class);

  private Slf4jLogConsumer sshdLogConsumer;

  @Container
  GenericContainer<?> sshd = new GenericContainer<>(
      new ImageFromDockerfile().withFileFromClasspath("ssh_host_rsa_key", "docker/ssh_host_rsa_key")
          .withFileFromClasspath("ssh_host_rsa_key.pub", "docker/ssh_host_rsa_key.pub")
          .withFileFromClasspath("ssh_host_ecdsa256_key", "docker/ssh_host_ecdsa256_key")
          .withFileFromClasspath("ssh_host_ecdsa256_key.pub", "docker/ssh_host_ecdsa256_key.pub")
          .withFileFromClasspath("ssh_host_ecdsa384_key", "docker/ssh_host_ecdsa384_key")
          .withFileFromClasspath("ssh_host_ecdsa384_key.pub", "docker/ssh_host_ecdsa384_key.pub")
          .withFileFromClasspath("ssh_host_ecdsa521_key", "docker/ssh_host_ecdsa521_key")
          .withFileFromClasspath("ssh_host_ecdsa521_key.pub", "docker/ssh_host_ecdsa521_key.pub")
          .withFileFromClasspath("ssh_host_ed25519_key", "docker/ssh_host_ed25519_key")
          .withFileFromClasspath("ssh_host_ed25519_key.pub", "docker/ssh_host_ed25519_key.pub")
          .withFileFromClasspath("sshd_config", "docker/sshd_config.openssh99")
          .withFileFromClasspath("authorized_keys", "docker/authorized_keys")
          .withFileFromClasspath("Dockerfile", "docker/Dockerfile.openssh99"))
      .withExposedPorts(22);

  @BeforeAll
  static void beforeAll() {
    JSch.setLogger(new Slf4jLogger());
  }

  @BeforeEach
  void beforeEach() {
    if (sshdLogConsumer == null) {
      sshdLogConsumer = new Slf4jLogConsumer(sshdLogger);
      sshd.followOutput(sshdLogConsumer);
    }

    jschLogger.clearAll();
    sshdLogger.clearAll();
  }

  @AfterAll
  static void afterAll() {
    JSch.setLogger(null);
    jschLogger.clearAll();
    sshdLogger.clearAll();
  }

  @Test
  void testOneAndTwoHopsFromConfig() throws Exception {
    JSch ssh = createRSAIdentity();
    ssh.setConfigRepository(OpenSSHConfig.parse(String.join("\n", //
        "Host jump", "  HostName " + sshd.getHost(), "  Port " + sshd.getFirstMappedPort(),
        "  User root", "  StrictHostKeyChecking yes", "  PreferredAuthentications publickey",
        "Host inner", "  HostName 127.0.0.1", "  Port 22", "  User root",
        "  StrictHostKeyChecking yes", "  PreferredAuthentications publickey", //
        "Host one-hop", "  HostName 127.0.0.1", "  Port 22", "  User root", "  ProxyJump jump",
        "  StrictHostKeyChecking yes", "  PreferredAuthentications publickey", //
        "Host two-hops", "  HostName 127.0.0.1", "  Port 22", "  User root",
        "  ProxyJump jump,inner", "  StrictHostKeyChecking yes",
        "  PreferredAuthentications publickey", "")));

    for (String alias : new String[] {"one-hop", "two-hops"}) {
      Session session = ssh.getSession(alias);
      try {
        session.setTimeout(TIMEOUT);
        session.connect(TIMEOUT);
        assertTrue(session.isConnected(), alias);
        assertEquals("root", exec(session, "whoami"), alias);
        assertTrue(exec(session, "echo $SSH_CONNECTION").startsWith("127.0.0.1 "),
            alias + " arrived through the hop");
      } catch (Exception e) {
        printInfo();
        throw e;
      } finally {
        session.disconnect();
      }
    }
  }

  @Test
  void testThroughLeavesHopToCaller() throws Exception {
    JSch ssh = createRSAIdentity();
    Session hop = ssh.getSession("root", sshd.getHost(), sshd.getFirstMappedPort());
    hop.setConfig("StrictHostKeyChecking", "yes");
    hop.setConfig("PreferredAuthentications", "publickey");
    try {
      hop.connect(TIMEOUT);
      Session target = createTargetSession(ssh, ProxyJump.through(hop));
      target.connect(TIMEOUT);
      assertEquals("root", exec(target, "whoami"));
      target.disconnect();
      assertTrue(hop.isConnected(), "closing the target does not close a caller-owned hop");
      assertEquals("root", exec(hop, "whoami"));
    } catch (Exception e) {
      printInfo();
      throw e;
    } finally {
      hop.disconnect();
    }
  }

  private Session createTargetSession(JSch ssh, Proxy proxy) throws Exception {
    Session session = ssh.getSession("root", "127.0.0.1", 22);
    session.setConfig("StrictHostKeyChecking", "yes");
    session.setConfig("PreferredAuthentications", "publickey");
    session.setProxy(proxy);
    session.setTimeout(TIMEOUT);
    return session;
  }

  private static String exec(Session session, String command) throws Exception {
    ChannelExec channel = (ChannelExec) session.openChannel("exec");
    channel.setCommand(command);
    InputStream in = channel.getInputStream();
    channel.connect(TIMEOUT);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    for (int n; (n = in.read(buffer)) >= 0;) {
      out.write(buffer, 0, n);
    }
    channel.disconnect();
    return new String(out.toByteArray(), UTF_8).trim();
  }

  private JSch createRSAIdentity() throws Exception {
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_rsa"), getResourceFile("docker/id_rsa.pub"), null);
    String publicKey = getResourceFile("docker/ssh_host_rsa_key.pub");
    // The hop is known by its mapped port on the host, the target by its address inside the hop.
    ssh.getHostKeyRepository().add(
        readHostKey(publicKey,
            String.format(Locale.ROOT, "[%s]:%d", sshd.getHost(), sshd.getFirstMappedPort())),
        null);
    ssh.getHostKeyRepository().add(readHostKey(publicKey, "127.0.0.1"), null);
    return ssh;
  }

  private static HostKey readHostKey(String fileName, String hostname) throws Exception {
    List<String> lines = Files.readAllLines(Paths.get(fileName), UTF_8);
    String[] split = lines.get(0).split("\\s+");
    return new HostKey(hostname, Base64.getDecoder().decode(split[1]));
  }

  private static String getResourceFile(String fileName) {
    return ResourceUtil.getResourceFile(ProxyJumpIT.class, fileName);
  }

  private void printInfo() {
    jschLogger.getAllLoggingEvents().stream().map(LoggingEvent::getFormattedMessage)
        .forEach(System.out::println);
    sshdLogger.getAllLoggingEvents().stream().map(LoggingEvent::getFormattedMessage)
        .forEach(System.out::println);
    System.out.println("");
  }
}
