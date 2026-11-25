package com.jcraft.jsch;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.valfirst.slf4jtest.LoggingEvent;
import com.github.valfirst.slf4jtest.TestLogger;
import com.github.valfirst.slf4jtest.TestLoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Random;

import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.event.Level;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Integration tests for ShangMi (SM4/SM3) cipher and MAC support. Uses an openEuler SSH server that
 * supports SM4 ciphers and HMAC-SM3 MACs natively.
 */
@Testcontainers
class AlgorithmsShangMiIT {

  private static final int timeout = 10000;
  private static final DigestUtils sha256sum = new DigestUtils(DigestUtils.getSha256Digest());
  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger =
      TestLoggerFactory.getTestLogger(AlgorithmsShangMiIT.class);

  @TempDir
  public Path tmpDir;
  private Path in;
  private Path out;
  private String hash;
  private Slf4jLogConsumer sshdLogConsumer;

  @Container
  public GenericContainer<?> sshd = new GenericContainer<>(
      new ImageFromDockerfile().withFileFromClasspath("ssh_host_sm2_key", "docker/ssh_host_sm2_key")
          .withFileFromClasspath("ssh_host_sm2_key.pub", "docker/ssh_host_sm2_key.pub")
          .withFileFromClasspath("sshd_config.shangmi", "docker/sshd_config.shangmi")
          .withFileFromClasspath("authorized_keys", "docker/authorized_keys")
          .withFileFromClasspath("Dockerfile", "docker/Dockerfile.openeuler.shangmi"))
      .withExposedPorts(22);

  @BeforeAll
  static void beforeAll() {
    jschLogger.setEnabledLevelsForAllThreads(Level.DEBUG, Level.INFO, Level.WARN, Level.ERROR);
    sshdLogger.setEnabledLevelsForAllThreads(Level.DEBUG, Level.INFO, Level.WARN, Level.ERROR);
    JSch.setLogger(new Slf4jLogger());
  }

  @BeforeEach
  void beforeEach() throws IOException {
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
  static void afterAll() {
    JSch.setLogger(null);
    jschLogger.clearAll();
    sshdLogger.clearAll();
  }

  @ParameterizedTest
  @ValueSource(strings = {"sm2-sm3"})
  void testSM2SM3Kex(String kex) throws Exception {
    JSch ssh = createsm2Identity();
    Session session = createSession(ssh);
    session.setConfig("kex", kex);
    doSftp(session, true);

    checkLogs(String.format(Locale.ROOT, "kex: algorithm: %s.*", kex));
  }

  @ParameterizedTest
  @ValueSource(strings = {"sm4-ctr"})
  void testSM4Ciphers(String cipher) throws Exception {

    JSch ssh = createsm2Identity();
    Session session = createSession(ssh);
    session.setConfig("cipher.s2c", cipher);
    session.setConfig("cipher.c2s", cipher);
    session.setConfig("mac.s2c", "hmac-sha2-256");
    session.setConfig("mac.c2s", "hmac-sha2-256");
    doSftp(session, true);

    String expectedS2C = String.format(Locale.ROOT, "kex: server->client cipher: %s.*", cipher);
    String expectedC2S = String.format(Locale.ROOT, "kex: client->server cipher: %s.*", cipher);
    checkLogs(expectedS2C);
    checkLogs(expectedC2S);
  }

  @ParameterizedTest
  @ValueSource(strings = {"hmac-sm3"})
  void testSM3MACs(String mac) throws Exception {
    JSch ssh = createsm2Identity();
    Session session = createSession(ssh);
    session.setConfig("cipher.s2c", "aes128-ctr");
    session.setConfig("cipher.c2s", "aes128-ctr");
    session.setConfig("mac.s2c", mac);
    session.setConfig("mac.c2s", mac);
    doSftp(session, true);

    String expectedS2C = String.format(Locale.ROOT, "kex: server->client .* MAC: %s.*", mac);
    String expectedC2S = String.format(Locale.ROOT, "kex: client->server .* MAC: %s.*", mac);
    checkLogs(expectedS2C);
    checkLogs(expectedC2S);
  }

  @ParameterizedTest
  @CsvSource(value = {"sm4-ctr,hmac-sm3"})
  void testSM4CipherWithSM3MAC(String cipher, String mac) throws Exception {
    JSch ssh = createsm2Identity();
    Session session = createSession(ssh);
    session.setConfig("cipher.s2c", cipher);
    session.setConfig("cipher.c2s", cipher);
    session.setConfig("mac.s2c", mac);
    session.setConfig("mac.c2s", mac);
    doSftp(session, true);

    checkLogs(String.format(Locale.ROOT, "kex: server->client cipher: %s.*", cipher));
    checkLogs(String.format(Locale.ROOT, "kex: client->server cipher: %s.*", cipher));
    checkLogs(String.format(Locale.ROOT, "kex: server->client .* MAC: %s.*", mac));
    checkLogs(String.format(Locale.ROOT, "kex: client->server .* MAC: %s.*", mac));
  }

  private JSch createsm2Identity() throws Exception {
    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_sm2_key.pub"));
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_sm2"), getResourceFile("docker/id_sm2.pub"), null);
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
    session.setConfig("server_host_key", "sm2");
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

  private void printInfo() {
    printEvents("JSch", jschLogger.getAllLoggingEvents());
    printEvents("sshd", sshdLogger.getAllLoggingEvents());
  }

  private void checkLogs(String expected) {
    boolean actualJsch = jschLogger.getAllLoggingEvents().stream()
        .map(LoggingEvent::getFormattedMessage).anyMatch(msg -> msg.matches(expected));

    if (!actualJsch) {
      printInfo();
    }

    assertTrue(actualJsch, () -> "Expected log message matching: " + expected);
  }

  private static void printEvents(String source, List<LoggingEvent> events) {
    events.stream().map(LoggingEvent::getFormattedMessage)
        .forEach(msg -> System.err.println("[" + source + "] " + msg));
  }

  private static String getResourceFile(String fileName) {
    return Paths.get("src", "test", "resources", fileName).toAbsolutePath().toString();
  }
}
