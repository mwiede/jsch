package com.jcraft.jsch;

import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.condition.JRE.JAVA_11;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
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
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
public class AlgorithmsIT {

  private static final int timeout = 1000;
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
                  .withFileFromClasspath("ssh_host_dsa_key", "docker/ssh_host_dsa_key")
                  .withFileFromClasspath("ssh_host_dsa_key.pub", "docker/ssh_host_dsa_key.pub")
                  .withFileFromClasspath("sshd_config", "docker/sshd_config")
                  .withFileFromClasspath("authorized_keys", "docker/authorized_keys")
                  .withFileFromClasspath("Dockerfile", "docker/Dockerfile"))
          .withExposedPorts(22);

  @BeforeAll
  public static void beforeAll() {
    JSch.setLogger(Slf4jLogger.getInstance());
  }

  @BeforeEach
  public void beforeEach() throws IOException {
    if (sshdLogConsumer == null) {
      sshdLogConsumer = new Slf4jLogConsumer(LoggerFactory.getLogger(AlgorithmsIT.class));
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
  @ValueSource(strings = {"curve25519-sha256", "curve25519-sha256@libssh.org"})
  @EnabledForJreRange(min = JAVA_11)
  public void testJava11KEXs(String kex) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("kex", kex);
    doSftp(session, true);

    String expected = String.format("kex: algorithm: %s.*", kex);
    checkLogs(expected);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "ecdh-sha2-nistp521",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp256",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group1-sha1"
      })
  public void testKEXs(String kex) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("kex", kex);
    doSftp(session, true);

    String expected = String.format("kex: algorithm: %s.*", kex);
    checkLogs(expected);
  }

  @Test
  public void testECDSA521() throws Exception {
    JSch ssh = createECDSA521Identity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedKeyTypes", "ecdsa-sha2-nistp521");
    session.setConfig("server_host_key", "ecdsa-sha2-nistp521");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ecdsa-sha2-nistp521.*";
    checkLogs(expected);
  }

  @Test
  public void testECDSA384() throws Exception {
    JSch ssh = createECDSA384Identity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedKeyTypes", "ecdsa-sha2-nistp384");
    session.setConfig("server_host_key", "ecdsa-sha2-nistp384");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ecdsa-sha2-nistp384.*";
    checkLogs(expected);
  }

  @Test
  public void testECDSA256() throws Exception {
    JSch ssh = createECDSA256Identity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedKeyTypes", "ecdsa-sha2-nistp256");
    session.setConfig("server_host_key", "ecdsa-sha2-nistp256");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ecdsa-sha2-nistp256.*";
    checkLogs(expected);
  }

  @ParameterizedTest
  @ValueSource(strings = {"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"})
  public void testRSA(String keyType) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedKeyTypes", keyType);
    session.setConfig("server_host_key", keyType);
    doSftp(session, true);

    String expected = String.format("kex: host key algorithm: %s.*", keyType);
    checkLogs(expected);
  }

  @Test
  public void testDSA() throws Exception {
    JSch ssh = createDSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedKeyTypes", "ssh-dss");
    session.setConfig("server_host_key", "ssh-dss");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ssh-dss.*";
    checkLogs(expected);
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "aes256-gcm@openssh.com,none",
        "aes256-gcm@openssh.com,zlib@openssh.com",
        "aes128-gcm@openssh.com,none",
        "aes128-gcm@openssh.com,zlib@openssh.com",
        "aes256-ctr,none",
        "aes256-ctr,zlib@openssh.com",
        "aes192-ctr,none",
        "aes192-ctr,zlib@openssh.com",
        "aes128-ctr,none",
        "aes128-ctr,zlib@openssh.com",
        "aes256-cbc,none",
        "aes256-cbc,zlib@openssh.com",
        "aes192-cbc,none",
        "aes192-cbc,zlib@openssh.com",
        "aes128-cbc,none",
        "aes128-cbc,zlib@openssh.com",
        "3des-cbc,none",
        "3des-cbc,zlib@openssh.com",
        "blowfish-cbc,none",
        "blowfish-cbc,zlib@openssh.com",
        "arcfour,none",
        "arcfour,zlib@openssh.com",
        "arcfour256,none",
        "arcfour256,zlib@openssh.com",
        "arcfour128,none",
        "arcfour128,zlib@openssh.com"
      })
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

  @ParameterizedTest
  @CsvSource(
      value = {
        "hmac-sha2-512-etm@openssh.com,none",
        "hmac-sha2-512-etm@openssh.com,zlib@openssh.com",
        "hmac-sha2-256-etm@openssh.com,none",
        "hmac-sha2-256-etm@openssh.com,zlib@openssh.com",
        "hmac-sha1-etm@openssh.com,none",
        "hmac-sha1-etm@openssh.com,zlib@openssh.com",
        "hmac-sha1-96-etm@openssh.com,none",
        "hmac-sha1-96-etm@openssh.com,zlib@openssh.com",
        "hmac-md5-etm@openssh.com,none",
        "hmac-md5-etm@openssh.com,zlib@openssh.com",
        "hmac-md5-96-etm@openssh.com,none",
        "hmac-md5-96-etm@openssh.com,zlib@openssh.com",
        "hmac-sha2-512,none",
        "hmac-sha2-512,zlib@openssh.com",
        "hmac-sha2-256,none",
        "hmac-sha2-256,zlib@openssh.com",
        "hmac-sha1,none",
        "hmac-sha1,zlib@openssh.com",
        "hmac-sha1-96,none",
        "hmac-sha1-96,zlib@openssh.com",
        "hmac-md5,none",
        "hmac-md5,zlib@openssh.com",
        "hmac-md5-96,none",
        "hmac-md5-96,zlib@openssh.com"
      })
  public void testMACs(String mac, String compression) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("mac.s2c", mac);
    session.setConfig("mac.c2s", mac);
    session.setConfig("compression.s2c", compression);
    session.setConfig("compression.c2s", compression);
    // Make sure a non-AEAD cipher is used
    session.setConfig("cipher.s2c", "aes128-ctr");
    session.setConfig("cipher.c2s", "aes128-ctr");
    doSftp(session, true);

    String expectedS2C = String.format("kex: server->client .* MAC: %s.*", mac);
    String expectedC2S = String.format("kex: client->server .* MAC: %s.*", mac);
    checkLogs(expectedS2C);
    checkLogs(expectedC2S);
  }

  // Note: OpenSSH does not support zlib
  @ParameterizedTest
  @ValueSource(strings = {"zlib@openssh.com", "none"})
  public void testCompressions(String compression) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("compression.s2c", compression);
    session.setConfig("compression.c2s", compression);
    doSftp(session, true);

    String expectedS2C = String.format("kex: server->client .* compression: %s.*", compression);
    String expectedC2S = String.format("kex: client->server .* compression: %s.*", compression);
    checkLogs(expectedS2C);
    checkLogs(expectedC2S);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "SHA512:EyyvMhUehzuELz3ySpqMw2UggtNqVmWnTSrQy2x4FLT7aF1lmqKC30oF+VUOLhvTmFHYaDLLN9UnpuGphIltKQ",
        "SHA384:CMxHNJ/xzOfsmNqw4g6Be+ltVZX3ixtplON7nOspNlji0iMnWzM7X4SelzcpP7Ap",
        "SHA256:iqNO6JDjrpga8TvgBKGReaKEnGoF/1csoxWp/DV5xJ0",
        "SHA1:FO2EB514+YMk4jTFmNGOwscY2Pk",
        "MD5:3b:50:5b:c5:53:66:8c:2c:98:9b:ee:3f:19:0a:ff:29"
      })
  public void testFingerprintHashes(String fingerprint) throws Exception {
    String[] split = fingerprint.split(":");
    String hash = split[0];
    MockUserInfo userInfo = new MockUserInfo();
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedKeyTypes", "ssh-rsa");
    session.setConfig("server_host_key", "ssh-rsa");
    session.setConfig("StrictHostKeyChecking", "ask");
    session.setConfig("FingerprintHash", hash);
    session.setUserInfo(userInfo);
    try {
      doSftp(session, false);
    } catch (JSchException expected) {
    }

    String expected = String.format("RSA key fingerprint is %s.", fingerprint);
    List<String> msgs =
        userInfo.getMessages().stream()
            .map(msg -> msg.split("\n"))
            .flatMap(Arrays::stream)
            .collect(toList());
    Optional<String> actual = msgs.stream().filter(msg -> msg.equals(expected)).findFirst();

    if (!actual.isPresent()) {
      msgs.forEach(System.out::println);
      printInfo();
    }

    assertTrue(actual.isPresent());
  }

  private JSch createRSAIdentity() throws Exception {
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_rsa"), getResourceFile("docker/id_rsa.pub"), null);
    return ssh;
  }

  private JSch createECDSA256Identity() throws Exception {
    JSch ssh = new JSch();
    ssh.addIdentity(
        getResourceFile("docker/id_ecdsa256"), getResourceFile("docker/id_ecdsa256.pub"), null);
    return ssh;
  }

  private JSch createECDSA384Identity() throws Exception {
    JSch ssh = new JSch();
    ssh.addIdentity(
        getResourceFile("docker/id_ecdsa384"), getResourceFile("docker/id_ecdsa384.pub"), null);
    return ssh;
  }

  private JSch createECDSA521Identity() throws Exception {
    JSch ssh = new JSch();
    ssh.addIdentity(
        getResourceFile("docker/id_ecdsa521"), getResourceFile("docker/id_ecdsa521.pub"), null);
    return ssh;
  }

  private JSch createDSAIdentity() throws Exception {
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_dsa"), getResourceFile("docker/id_dsa.pub"), null);
    return ssh;
  }

  private Session createSession(JSch ssh) throws Exception {
    Session session = ssh.getSession("root", sshd.getHost(), sshd.getFirstMappedPort());
    session.setConfig("StrictHostKeyChecking", "no");
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
    Optional<String> actualSshd =
        sshdAppender.list.stream()
            .map(ILoggingEvent::getFormattedMessage)
            .filter(msg -> msg.matches("STDERR: debug1: " + expected))
            .findFirst();
    assertTrue(actualJsch.isPresent(), () -> "JSch: " + expected);
    assertTrue(actualSshd.isPresent(), () -> "sshd: " + expected);
  }

  private String getResourceFile(String fileName) {
    return this.getClass().getClassLoader().getResource(fileName).getPath();
  }

  private static ListAppender<ILoggingEvent> getListAppender(Class clazz) {
    Logger logger = (Logger) LoggerFactory.getLogger(clazz);
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    logger.addAppender(listAppender);
    return listAppender;
  }
}
