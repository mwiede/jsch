package com.jcraft.jsch;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.github.valfirst.slf4jtest.LoggingEvent;
import com.github.valfirst.slf4jtest.TestLogger;
import com.github.valfirst.slf4jtest.TestLoggerFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
public class ExitIT {

  private static final int timeout = 2000;
  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger = TestLoggerFactory.getTestLogger(ExitIT.class);

  private Slf4jLogConsumer sshdLogConsumer;

  @Container
  public GenericContainer<?> sshd = new GenericContainer<>(
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
  public static void beforeAll() {
    JSch.setLogger(new Slf4jLogger());
  }

  @BeforeEach
  public void beforeEach() throws IOException {
    if (sshdLogConsumer == null) {
      sshdLogConsumer = new Slf4jLogConsumer(sshdLogger);
      sshd.followOutput(sshdLogConsumer);
    }

    jschLogger.clearAll();
    sshdLogger.clearAll();
  }

  @AfterAll
  public static void afterAll() {
    JSch.setLogger(null);
    jschLogger.clearAll();
    sshdLogger.clearAll();
  }

  @Test
  public void testExitStatus() throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);

    try {
      session.setTimeout(timeout);
      session.connect();

      ChannelExec sleep = (ChannelExec) session.openChannel("exec");
      sleep.setCommand("sleep foobar");

      sleep.connect();

      for (int i = 0; i < 10; i++) {
        if (sleep.isClosed()) {
          break;
        } else {
          Thread.sleep(1000L);
        }
      }

      sleep.disconnect();
      session.disconnect();

      assertEquals(1, sleep.getExitStatus());
      assertEquals(null, sleep.getExitSignal());
    } catch (Exception e) {
      printInfo();
      throw e;
    }
  }

  @Test
  public void testExitSignal() throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);

    try {
      session.setTimeout(timeout);
      session.connect();

      ChannelExec sleep = (ChannelExec) session.openChannel("exec");
      sleep.setCommand("sleep 300");

      sleep.connect();
      Thread.sleep(1000L);
      ExecResult pkill = sshd.execInContainer("pkill", "-2", "sleep");

      for (int i = 0; i < 10; i++) {
        if (sleep.isClosed()) {
          break;
        } else {
          Thread.sleep(1000L);
        }
      }

      sleep.disconnect();
      session.disconnect();

      assertEquals(0, pkill.getExitCode());
      assertEquals("INT", sleep.getExitSignal());
      assertEquals(-1, sleep.getExitStatus());
    } catch (Exception e) {
      printInfo();
      throw e;
    }
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
