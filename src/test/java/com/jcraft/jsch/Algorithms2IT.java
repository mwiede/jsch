package com.jcraft.jsch;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.condition.JRE.JAVA_11;
import static org.junit.jupiter.api.condition.JRE.JAVA_15;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
public class Algorithms2IT {

  // Python can be slow, so use larger timeout.
  private static final int timeout = 2000;
  private static final DigestUtils sha256sum = new DigestUtils(DigestUtils.getSha256Digest());
  private static final ListAppender<ILoggingEvent> jschAppender = getListAppender(JSch.class);
  private static final ListAppender<ILoggingEvent> sshdAppender =
      getListAppender(AlgorithmsIT.class);

  @TempDir public Path tmpDir;
  private Path in;
  private Path out;
  private String hash;
  private Slf4jLogConsumer sshdLogConsumer;

  @Container
  public GenericContainer sshd =
      new GenericContainer(
              new ImageFromDockerfile()
                  .withFileFromClasspath("asyncsshd.py", "docker/asyncsshd.py")
                  .withFileFromClasspath("ssh_host_ed448_key", "docker/ssh_host_ed448_key")
                  .withFileFromClasspath("ssh_host_ed448_key.pub", "docker/ssh_host_ed448_key.pub")
                  .withFileFromClasspath("ssh_host_rsa_key", "docker/ssh_host_rsa_key")
                  .withFileFromClasspath("ssh_host_rsa_key.pub", "docker/ssh_host_rsa_key.pub")
                  .withFileFromClasspath("ssh_host_ecdsa256_key", "docker/ssh_host_ecdsa256_key")
                  .withFileFromClasspath(
                      "ssh_host_ecdsa256_key.pub", "docker/ssh_host_ecdsa256_key.pub")
                  .withFileFromClasspath("ssh_host_ecdsa384_key", "docker/ssh_host_ecdsa384_key")
                  .withFileFromClasspath(
                      "ssh_host_ecdsa384_key.pub", "docker/ssh_host_ecdsa384_key.pub")
                  .withFileFromClasspath("ssh_host_ecdsa521_key", "docker/ssh_host_ecdsa521_key")
                  .withFileFromClasspath(
                      "ssh_host_ecdsa521_key.pub", "docker/ssh_host_ecdsa521_key.pub")
                  .withFileFromClasspath("ssh_host_ed25519_key", "docker/ssh_host_ed25519_key")
                  .withFileFromClasspath(
                      "ssh_host_ed25519_key.pub", "docker/ssh_host_ed25519_key.pub")
                  .withFileFromClasspath("ssh_host_dsa_key", "docker/ssh_host_dsa_key")
                  .withFileFromClasspath("ssh_host_dsa_key.pub", "docker/ssh_host_dsa_key.pub")
                  .withFileFromClasspath("authorized_keys", "docker/authorized_keys")
                  .withFileFromClasspath("Dockerfile", "docker/Dockerfile.asyncssh"))
          .withExposedPorts(22);

  @BeforeAll
  public static void beforeAll() {
    JSch.setLogger(Slf4jLogger.getInstance());
  }

  @BeforeEach
  public void beforeEach() throws IOException {
    if (sshdLogConsumer == null) {
      sshdLogConsumer = new Slf4jLogConsumer(LoggerFactory.getLogger(Algorithms2IT.class));
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

    jschAppender.list.clear();
    sshdAppender.list.clear();
    jschAppender.start();
    sshdAppender.start();
  }

  @AfterEach
  public void afterEach() {
    jschAppender.stop();
    sshdAppender.stop();
    jschAppender.list.clear();
    sshdAppender.list.clear();
  }

  @Test
  @EnabledForJreRange(min = JAVA_11)
  public void testJava11KEXs() throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("kex", "curve448-sha512");
    doSftp(session, true);

    String expected = "kex: algorithm: curve448-sha512.*";
    checkLogs(expected);
  }

  @ParameterizedTest
  @ValueSource(strings = {"diffie-hellman-group17-sha512", "diffie-hellman-group15-sha512"})
  public void testKEXs(String kex) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("kex", kex);
    doSftp(session, true);

    String expected = String.format("kex: algorithm: %s.*", kex);
    checkLogs(expected);
  }

  @Test
  @EnabledForJreRange(min = JAVA_15)
  public void testEd448() throws Exception {
    JSch ssh = createEd448Identity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedKeyTypes", "ssh-ed448");
    session.setConfig("server_host_key", "ssh-ed448");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ssh-ed448.*";
    checkLogs(expected);
  }

  @Test
  public void testCompressions() throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("compression.s2c", "zlib");
    session.setConfig("compression.c2s", "zlib");
    doSftp(session, true);

    String expectedS2C = "kex: server->client .* compression: zlib.*";
    String expectedC2S = "kex: client->server .* compression: zlib.*";
    checkLogs(expectedS2C);
    checkLogs(expectedC2S);
  }

  private JSch createRSAIdentity() throws Exception {
    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_rsa_key.pub"));
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_rsa"), getResourceFile("docker/id_rsa.pub"), null);
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private JSch createEd448Identity() throws Exception {
    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_ed448_key.pub"));
    JSch ssh = new JSch();
    ssh.addIdentity(
        getResourceFile("docker/id_ed448"), getResourceFile("docker/id_ed448.pub"), null);
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private HostKey readHostKey(String fileName) throws Exception {
    List<String> lines = Files.readAllLines(Paths.get(fileName), UTF_8);
    String[] split = lines.get(0).split("\\s+");
    String hostname = String.format("[%s]:%d", sshd.getHost(), sshd.getFirstMappedPort());
    return new HostKey(hostname, decodeBase64(split[1]));
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
      jschAppender.stop();
      sshdAppender.stop();
    } catch (Exception e) {
      if (debugException) {
        printInfo();
      }
      throw e;
    }

    assertEquals(1024L * 100L, Files.size(out));
    assertEquals(hash, sha256sum.digestAsHex(out));
  }

  private static void printInfo() {
    jschAppender.stop();
    sshdAppender.stop();
    jschAppender.list.stream().map(ILoggingEvent::getFormattedMessage).forEach(System.out::println);
    sshdAppender.list.stream().map(ILoggingEvent::getFormattedMessage).forEach(System.out::println);
    System.out.println("");
    System.out.println("");
    System.out.println("");
  }

  private static void checkLogs(String expected) {
    Optional<String> actualJsch =
        jschAppender.list.stream()
            .map(ILoggingEvent::getFormattedMessage)
            .filter(msg -> msg.matches(expected))
            .findFirst();
    assertTrue(actualJsch.isPresent(), () -> "JSch: " + expected);
  }

  private String getResourceFile(String fileName) {
    return this.getClass().getClassLoader().getResource(fileName).getPath();
  }

  private static ListAppender<ILoggingEvent> getListAppender(Class<?> clazz) {
    Logger logger = (Logger) LoggerFactory.getLogger(clazz);
    ListAppender<ILoggingEvent> listAppender = new ListAppender2<>();
    logger.addAppender(listAppender);
    return listAppender;
  }
}
