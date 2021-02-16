package com.jcraft.jsch;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
public class Algorithms3IT {

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
  public GenericContainer<?> sshd =
      new GenericContainer<>(
              new ImageFromDockerfile()
                  .withFileFromClasspath("dropbear_rsa_host_key", "docker/dropbear_rsa_host_key")
                  .withFileFromClasspath("authorized_keys", "docker/authorized_keys")
                  .withFileFromClasspath("Dockerfile", "docker/Dockerfile.dropbear"))
          .withExposedPorts(22);

  @BeforeAll
  public static void beforeAll() {
    JSch.setLogger(Slf4jLogger.getInstance());
  }

  @BeforeEach
  public void beforeEach() throws IOException {
    if (sshdLogConsumer == null) {
      sshdLogConsumer = new Slf4jLogConsumer(LoggerFactory.getLogger(Algorithms3IT.class));
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

  @ParameterizedTest
  @CsvSource(value = {"3des-ctr,none", "3des-ctr,zlib@openssh.com"})
  public void testCiphers(String cipher, String compression) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("cipher.s2c", cipher);
    session.setConfig("cipher.c2s", cipher);
    session.setConfig("compression.s2c", compression);
    session.setConfig("compression.c2s", compression);
    doSftp(session, true);

    String expectedS2C = String.format("kex: server->client cipher: %s.*", cipher);
    String expectedC2S = String.format("kex: client->server cipher: %s.*", cipher);
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
      // Sleep for a short bit to allow logs from test container to catch up
      Thread.sleep(100L);
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
    try {
      assertTrue(actualJsch.isPresent(), () -> "JSch: " + expected);
    } catch (AssertionError e) {
      printInfo();
      throw e;
    }
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
