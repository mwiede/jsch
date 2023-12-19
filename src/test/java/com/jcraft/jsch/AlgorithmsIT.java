package com.jcraft.jsch;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.condition.JRE.JAVA_11;
import static org.junit.jupiter.api.condition.JRE.JAVA_15;

import com.github.valfirst.slf4jtest.LoggingEvent;
import com.github.valfirst.slf4jtest.TestLogger;
import com.github.valfirst.slf4jtest.TestLoggerFactory;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Random;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
public class AlgorithmsIT {

  private static final int timeout = 2000;
  private static final DigestUtils sha256sum = new DigestUtils(DigestUtils.getSha256Digest());
  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger = TestLoggerFactory.getTestLogger(AlgorithmsIT.class);

  @TempDir
  public Path tmpDir;
  private Path in;
  private Path out;
  private String hash;
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
          .withFileFromClasspath("ssh_host_dsa_key", "docker/ssh_host_dsa_key")
          .withFileFromClasspath("ssh_host_dsa_key.pub", "docker/ssh_host_dsa_key.pub")
          .withFileFromClasspath("sshd_config", "docker/sshd_config")
          .withFileFromClasspath("authorized_keys", "docker/authorized_keys")
          .withFileFromClasspath("Dockerfile", "docker/Dockerfile"))
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

  @ParameterizedTest
  @ValueSource(strings = {"curve25519-sha256", "curve25519-sha256@libssh.org"})
  @EnabledForJreRange(min = JAVA_11)
  public void testJava11KEXs(String kex) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("xdh", "com.jcraft.jsch.jce.XDH");
    session.setConfig("kex", kex);
    doSftp(session, true);

    String expected = String.format(Locale.ROOT, "kex: algorithm: %s.*", kex);
    checkLogs(expected);
  }

  @ParameterizedTest
  @ValueSource(strings = {"curve25519-sha256", "curve25519-sha256@libssh.org"})
  public void testBCKEXs(String kex) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("xdh", "com.jcraft.jsch.bc.XDH");
    session.setConfig("kex", kex);
    doSftp(session, true);

    String expected = String.format(Locale.ROOT, "kex: algorithm: %s.*", kex);
    checkLogs(expected);
  }

  @ParameterizedTest
  @ValueSource(strings = {"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp521",
      "ecdh-sha2-nistp384", "ecdh-sha2-nistp256", "diffie-hellman-group18-sha512",
      "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256",
      "diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1",
      "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"})
  public void testKEXs(String kex) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("kex", kex);
    doSftp(session, true);

    String expected = String.format(Locale.ROOT, "kex: algorithm: %s.*", kex);
    checkLogs(expected);
  }

  @ParameterizedTest
  @CsvSource(value = {"diffie-hellman-group-exchange-sha256,2048",
      "diffie-hellman-group-exchange-sha256,3072", "diffie-hellman-group-exchange-sha256,4096",
      "diffie-hellman-group-exchange-sha256,6144", "diffie-hellman-group-exchange-sha256,8192",
      "diffie-hellman-group-exchange-sha1,2048", "diffie-hellman-group-exchange-sha1,3072",
      "diffie-hellman-group-exchange-sha1,4096", "diffie-hellman-group-exchange-sha1,6144",
      "diffie-hellman-group-exchange-sha1,8192"})
  public void testDHGEXSizes(String kex, String size) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("kex", kex);
    session.setConfig("dhgex_min", size);
    session.setConfig("dhgex_max", size);
    session.setConfig("dhgex_preferred", size);
    doSftp(session, true);

    String expectedKex = String.format(Locale.ROOT, "kex: algorithm: %s.*", kex);
    String expectedSizes = String.format(Locale.ROOT,
        "SSH_MSG_KEX_DH_GEX_REQUEST\\(%s<%s<%s\\) sent", size, size, size);
    checkLogs(expectedKex);
    checkLogs(expectedSizes);
  }

  @Test
  @EnabledForJreRange(min = JAVA_15)
  public void testJava15Ed25519() throws Exception {
    JSch ssh = createEd25519Identity();
    Session session = createSession(ssh);
    session.setConfig("keypairgen.eddsa", "com.jcraft.jsch.jce.KeyPairGenEdDSA");
    session.setConfig("ssh-ed25519", "com.jcraft.jsch.jce.SignatureEd25519");
    session.setConfig("PubkeyAcceptedAlgorithms", "ssh-ed25519");
    session.setConfig("server_host_key", "ssh-ed25519");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ssh-ed25519.*";
    checkLogs(expected);
  }

  @Test
  public void testBCEd25519() throws Exception {
    JSch ssh = createEd25519Identity();
    Session session = createSession(ssh);
    session.setConfig("keypairgen.eddsa", "com.jcraft.jsch.bc.KeyPairGenEdDSA");
    session.setConfig("ssh-ed25519", "com.jcraft.jsch.bc.SignatureEd25519");
    session.setConfig("PubkeyAcceptedAlgorithms", "ssh-ed25519");
    session.setConfig("server_host_key", "ssh-ed25519");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ssh-ed25519.*";
    checkLogs(expected);
  }

  @Test
  public void testEd25519() throws Exception {
    JSch ssh = createEd25519Identity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ssh-ed25519");
    session.setConfig("server_host_key", "ssh-ed25519");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ssh-ed25519.*";
    checkLogs(expected);
  }

  @Test
  public void testECDSA521() throws Exception {
    JSch ssh = createECDSA521Identity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ecdsa-sha2-nistp521");
    session.setConfig("server_host_key", "ecdsa-sha2-nistp521");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ecdsa-sha2-nistp521.*";
    checkLogs(expected);
  }

  @Test
  public void testECDSA384() throws Exception {
    JSch ssh = createECDSA384Identity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ecdsa-sha2-nistp384");
    session.setConfig("server_host_key", "ecdsa-sha2-nistp384");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ecdsa-sha2-nistp384.*";
    checkLogs(expected);
  }

  @Test
  public void testECDSA256() throws Exception {
    JSch ssh = createECDSA256Identity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ecdsa-sha2-nistp256");
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
    session.setConfig("PubkeyAcceptedAlgorithms", keyType);
    session.setConfig("server_host_key", keyType);
    doSftp(session, true);

    String expected = String.format(Locale.ROOT, "kex: host key algorithm: %s.*", keyType);
    checkLogs(expected);
  }

  @Test
  public void testDSA() throws Exception {
    JSch ssh = createDSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ssh-dss");
    session.setConfig("server_host_key", "ssh-dss");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ssh-dss.*";
    checkLogs(expected);
  }

  @ParameterizedTest
  @CsvSource(value = {"chacha20-poly1305@openssh.com,none",
      "chacha20-poly1305@openssh.com,zlib@openssh.com", "aes256-gcm@openssh.com,none",
      "aes256-gcm@openssh.com,zlib@openssh.com", "aes128-gcm@openssh.com,none",
      "aes128-gcm@openssh.com,zlib@openssh.com", "aes256-ctr,none", "aes256-ctr,zlib@openssh.com",
      "aes192-ctr,none", "aes192-ctr,zlib@openssh.com", "aes128-ctr,none",
      "aes128-ctr,zlib@openssh.com", "aes256-cbc,none", "aes256-cbc,zlib@openssh.com",
      "aes192-cbc,none", "aes192-cbc,zlib@openssh.com", "aes128-cbc,none",
      "aes128-cbc,zlib@openssh.com", "3des-cbc,none", "3des-cbc,zlib@openssh.com",
      "blowfish-cbc,none", "blowfish-cbc,zlib@openssh.com", "arcfour,none",
      "arcfour,zlib@openssh.com", "arcfour256,none", "arcfour256,zlib@openssh.com",
      "arcfour128,none", "arcfour128,zlib@openssh.com", "rijndael-cbc@lysator.liu.se,none",
      "rijndael-cbc@lysator.liu.se,zlib@openssh.com", "cast128-cbc,none",
      "cast128-cbc,zlib@openssh.com"})
  public void testCiphers(String cipher, String compression) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("cipher.s2c", cipher);
    session.setConfig("cipher.c2s", cipher);
    session.setConfig("compression.s2c", compression);
    session.setConfig("compression.c2s", compression);
    doSftp(session, true);

    String expectedS2C = String.format(Locale.ROOT, "kex: server->client cipher: %s.*", cipher);
    String expectedC2S = String.format(Locale.ROOT, "kex: client->server cipher: %s.*", cipher);
    checkLogs(expectedS2C);
    checkLogs(expectedC2S);
  }

  @ParameterizedTest
  @CsvSource(value = {"hmac-sha2-512-etm@openssh.com,none",
      "hmac-sha2-512-etm@openssh.com,zlib@openssh.com", "hmac-sha2-256-etm@openssh.com,none",
      "hmac-sha2-256-etm@openssh.com,zlib@openssh.com", "hmac-sha1-etm@openssh.com,none",
      "hmac-sha1-etm@openssh.com,zlib@openssh.com", "hmac-sha1-96-etm@openssh.com,none",
      "hmac-sha1-96-etm@openssh.com,zlib@openssh.com", "hmac-md5-etm@openssh.com,none",
      "hmac-md5-etm@openssh.com,zlib@openssh.com", "hmac-md5-96-etm@openssh.com,none",
      "hmac-md5-96-etm@openssh.com,zlib@openssh.com", "hmac-sha2-512,none",
      "hmac-sha2-512,zlib@openssh.com", "hmac-sha2-256,none", "hmac-sha2-256,zlib@openssh.com",
      "hmac-sha1,none", "hmac-sha1,zlib@openssh.com", "hmac-sha1-96,none",
      "hmac-sha1-96,zlib@openssh.com", "hmac-md5,none", "hmac-md5,zlib@openssh.com",
      "hmac-md5-96,none", "hmac-md5-96,zlib@openssh.com", "hmac-ripemd160,none",
      "hmac-ripemd160,zlib@openssh.com", "hmac-ripemd160@openssh.com,none",
      "hmac-ripemd160@openssh.com,zlib@openssh.com", "hmac-ripemd160-etm@openssh.com,none",
      "hmac-ripemd160-etm@openssh.com,zlib@openssh.com"})
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

    String expectedS2C = String.format(Locale.ROOT, "kex: server->client .* MAC: %s.*", mac);
    String expectedC2S = String.format(Locale.ROOT, "kex: client->server .* MAC: %s.*", mac);
    checkLogs(expectedS2C);
    checkLogs(expectedC2S);
  }

  @ParameterizedTest
  @ValueSource(strings = {"zlib@openssh.com", "none"})
  public void testCompressions(String compression) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("compression.s2c", compression);
    session.setConfig("compression.c2s", compression);
    doSftp(session, true);

    String expectedS2C =
        String.format(Locale.ROOT, "kex: server->client .* compression: %s.*", compression);
    String expectedC2S =
        String.format(Locale.ROOT, "kex: client->server .* compression: %s.*", compression);
    checkLogs(expectedS2C);
    checkLogs(expectedC2S);
  }

  @ParameterizedTest
  @ValueSource(strings = {"com.jcraft.jsch.juz.Compression", "com.jcraft.jsch.jzlib.Compression"})
  public void testCompressionImpls(String impl) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("compression.s2c", "zlib@openssh.com");
    session.setConfig("compression.c2s", "zlib@openssh.com");
    session.setConfig("zlib@openssh.com", impl);
    doSftp(session, true);

    String expectedImpl = String.format(Locale.ROOT, "zlib using %s", impl);
    String expectedS2C = "kex: server->client .* compression: zlib@openssh\\.com.*";
    String expectedC2S = "kex: client->server .* compression: zlib@openssh\\.com.*";
    checkLogs(expectedImpl);
    checkLogs(expectedS2C);
    checkLogs(expectedC2S);
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "SHA512:EyyvMhUehzuELz3ySpqMw2UggtNqVmWnTSrQy2x4FLT7aF1lmqKC30oF+VUOLhvTmFHYaDLLN9UnpuGphIltKQ",
      "SHA384:CMxHNJ/xzOfsmNqw4g6Be+ltVZX3ixtplON7nOspNlji0iMnWzM7X4SelzcpP7Ap",
      "SHA256:iqNO6JDjrpga8TvgBKGReaKEnGoF/1csoxWp/DV5xJ0",
      "SHA224:mJNHjKtQuiRHioFZIGj1g/+fcKMOsKmzcokU2w", "SHA1:FO2EB514+YMk4jTFmNGOwscY2Pk",
      "MD5:3b:50:5b:c5:53:66:8c:2c:98:9b:ee:3f:19:0a:ff:29"})
  public void testFingerprintHashes(String fingerprint) throws Exception {
    String[] split = fingerprint.split(":");
    String hash = split[0];
    MockUserInfo userInfo = new MockUserInfo();
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_rsa"), getResourceFile("docker/id_rsa.pub"), null);
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ssh-rsa");
    session.setConfig("server_host_key", "ssh-rsa");
    session.setConfig("StrictHostKeyChecking", "ask");
    session.setConfig("FingerprintHash", hash);
    session.setUserInfo(userInfo);
    try {
      doSftp(session, false);
    } catch (JSchException expected) {
    }

    String expected = String.format(Locale.ROOT, "RSA key fingerprint is %s.", fingerprint);
    List<String> msgs = userInfo.getMessages().stream().map(msg -> msg.split("\n"))
        .flatMap(Arrays::stream).collect(toList());
    Optional<String> actual = msgs.stream().filter(msg -> msg.equals(expected)).findFirst();

    if (!actual.isPresent()) {
      msgs.forEach(System.out::println);
      printInfo();
    }

    assertTrue(actual.isPresent());
  }

  private JSch createRSAIdentity() throws Exception {
    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_rsa_key.pub"));
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_rsa"), getResourceFile("docker/id_rsa.pub"), null);
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private JSch createECDSA256Identity() throws Exception {
    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_ecdsa256_key.pub"));
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_ecdsa256"),
        getResourceFile("docker/id_ecdsa256.pub"), null);
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private JSch createECDSA384Identity() throws Exception {
    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_ecdsa384_key.pub"));
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_ecdsa384"),
        getResourceFile("docker/id_ecdsa384.pub"), null);
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private JSch createECDSA521Identity() throws Exception {
    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_ecdsa521_key.pub"));
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_ecdsa521"),
        getResourceFile("docker/id_ecdsa521.pub"), null);
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private JSch createDSAIdentity() throws Exception {
    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_dsa_key.pub"));
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_dsa"), getResourceFile("docker/id_dsa.pub"), null);
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private JSch createEd25519Identity() throws Exception {
    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_ed25519_key.pub"));
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile("docker/id_ed25519"), getResourceFile("docker/id_ed25519.pub"),
        null);
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

  private void printInfo() {
    jschLogger.getAllLoggingEvents().stream().map(LoggingEvent::getFormattedMessage)
        .forEach(System.out::println);
    sshdLogger.getAllLoggingEvents().stream().map(LoggingEvent::getFormattedMessage)
        .forEach(System.out::println);
    System.out.println("");
    System.out.println("");
    System.out.println("");
  }

  private void checkLogs(String expected) {
    Optional<String> actualJsch = jschLogger.getAllLoggingEvents().stream()
        .map(LoggingEvent::getFormattedMessage).filter(msg -> msg.matches(expected)).findFirst();
    // Skip OpenSSH log checks, as log output from Docker falls behind and these assertions
    // frequently run before they are output
    // Optional<String> actualSshd =
    // sshdLogger.getAllLoggingEvents().stream()
    // .map(LoggingEvent::getFormattedMessage)
    // .filter(msg -> msg.matches("STDERR: debug1: " + expected))
    // .findFirst();
    try {
      assertTrue(actualJsch.isPresent(), () -> "JSch: " + expected);
      // assertTrue(actualSshd.isPresent(), () -> "sshd: " + expected);
    } catch (AssertionError e) {
      printInfo();
      throw e;
    }
  }

  private String getResourceFile(String fileName) {
    return ResourceUtil.getResourceFile(getClass(), fileName);
  }
}
