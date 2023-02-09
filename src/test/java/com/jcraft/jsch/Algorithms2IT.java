package com.jcraft.jsch;

import static java.nio.charset.StandardCharsets.UTF_8;
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
import java.util.Base64;
import java.util.List;
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
public class Algorithms2IT {

  // Python can be slow for DH group 18
  private static final int timeout = 10000;
  private static final DigestUtils sha256sum = new DigestUtils(DigestUtils.getSha256Digest());
  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger = TestLoggerFactory.getTestLogger(Algorithms2IT.class);

  @TempDir
  public Path tmpDir;
  private Path in;
  private Path out;
  private String hash;
  private Slf4jLogConsumer sshdLogConsumer;

  @Container
  public GenericContainer<?> sshd = new GenericContainer<>(
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
          .withFileFromClasspath("Dockerfile", "docker/Dockerfile.asyncssh"))
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

  @Test
  @EnabledForJreRange(min = JAVA_11)
  public void testJava11KEXs() throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("xdh", "com.jcraft.jsch.jce.XDH");
    session.setConfig("kex", "curve448-sha512");
    doSftp(session, true);

    String expected = "kex: algorithm: curve448-sha512.*";
    checkLogs(expected);
  }

  @Test
  public void testBCKEXs() throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("xdh", "com.jcraft.jsch.bc.XDH");
    session.setConfig("kex", "curve448-sha512");
    doSftp(session, true);

    String expected = "kex: algorithm: curve448-sha512.*";
    checkLogs(expected);
  }

  @ParameterizedTest
  @ValueSource(strings = {"curve448-sha512", "diffie-hellman-group17-sha512",
      "diffie-hellman-group15-sha512", "diffie-hellman-group18-sha512@ssh.com",
      "diffie-hellman-group16-sha512@ssh.com", "diffie-hellman-group16-sha384@ssh.com",
      "diffie-hellman-group15-sha384@ssh.com", "diffie-hellman-group15-sha256@ssh.com",
      "diffie-hellman-group14-sha256@ssh.com", "diffie-hellman-group14-sha224@ssh.com",
      "diffie-hellman-group-exchange-sha512@ssh.com",
      "diffie-hellman-group-exchange-sha384@ssh.com",
      "diffie-hellman-group-exchange-sha224@ssh.com"})
  public void testKEXs(String kex) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("kex", kex);
    doSftp(session, true);

    String expected = String.format("kex: algorithm: %s.*", kex);
    checkLogs(expected);
  }

  @ParameterizedTest
  @CsvSource(value = {"diffie-hellman-group-exchange-sha256,1024",
      "diffie-hellman-group-exchange-sha1,1024",
      "diffie-hellman-group-exchange-sha512@ssh.com,1024",
      "diffie-hellman-group-exchange-sha512@ssh.com,2048",
      "diffie-hellman-group-exchange-sha512@ssh.com,4096",
      "diffie-hellman-group-exchange-sha512@ssh.com,6144",
      "diffie-hellman-group-exchange-sha512@ssh.com,8192",
      "diffie-hellman-group-exchange-sha384@ssh.com,1024",
      "diffie-hellman-group-exchange-sha384@ssh.com,2048",
      "diffie-hellman-group-exchange-sha384@ssh.com,4096",
      "diffie-hellman-group-exchange-sha384@ssh.com,6144",
      "diffie-hellman-group-exchange-sha384@ssh.com,8192",
      "diffie-hellman-group-exchange-sha224@ssh.com,1024",
      "diffie-hellman-group-exchange-sha224@ssh.com,2048",
      "diffie-hellman-group-exchange-sha224@ssh.com,4096",
      "diffie-hellman-group-exchange-sha224@ssh.com,6144",
      "diffie-hellman-group-exchange-sha224@ssh.com,8192"})
  public void testDHGEXSizes(String kex, String size) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("kex", kex);
    session.setConfig("dhgex_min", size);
    session.setConfig("dhgex_max", size);
    session.setConfig("dhgex_preferred", size);
    doSftp(session, true);

    String expectedKex = String.format("kex: algorithm: %s.*", kex);
    String expectedSizes =
        String.format("SSH_MSG_KEX_DH_GEX_REQUEST\\(%s<%s<%s\\) sent", size, size, size);
    checkLogs(expectedKex);
    checkLogs(expectedSizes);
  }

  @Test
  @EnabledForJreRange(min = JAVA_15)
  public void testJava15Ed448() throws Exception {
    JSch ssh = createEd448Identity();
    Session session = createSession(ssh);
    session.setConfig("keypairgen.eddsa", "com.jcraft.jsch.jce.KeyPairGenEdDSA");
    session.setConfig("ssh-ed448", "com.jcraft.jsch.jce.SignatureEd448");
    session.setConfig("PubkeyAcceptedAlgorithms", "ssh-ed448");
    session.setConfig("server_host_key", "ssh-ed448");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ssh-ed448.*";
    checkLogs(expected);
  }

  @Test
  public void testBCEd448() throws Exception {
    JSch ssh = createEd448Identity();
    Session session = createSession(ssh);
    session.setConfig("keypairgen.eddsa", "com.jcraft.jsch.bc.KeyPairGenEdDSA");
    session.setConfig("ssh-ed448", "com.jcraft.jsch.bc.SignatureEd448");
    session.setConfig("PubkeyAcceptedAlgorithms", "ssh-ed448");
    session.setConfig("server_host_key", "ssh-ed448");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ssh-ed448.*";
    checkLogs(expected);
  }

  @Test
  public void testEd448() throws Exception {
    JSch ssh = createEd448Identity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ssh-ed448");
    session.setConfig("server_host_key", "ssh-ed448");
    doSftp(session, true);

    String expected = "kex: host key algorithm: ssh-ed448.*";
    checkLogs(expected);
  }

  @ParameterizedTest
  @ValueSource(strings = {"ssh-rsa-sha512@ssh.com", "ssh-rsa-sha384@ssh.com",
      "ssh-rsa-sha256@ssh.com", "ssh-rsa-sha224@ssh.com"})
  public void testRSA(String keyType) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", keyType);
    session.setConfig("server_host_key", keyType);
    doSftp(session, true);

    String expected = String.format("kex: host key algorithm: %s.*", keyType);
    checkLogs(expected);
  }

  @ParameterizedTest
  @CsvSource(value = {"seed-cbc@ssh.com,none", "seed-cbc@ssh.com,zlib@openssh.com"})
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
  @CsvSource(value = {"hmac-sha512@ssh.com,none", "hmac-sha512@ssh.com,zlib@openssh.com",
      "hmac-sha384@ssh.com,none", "hmac-sha384@ssh.com,zlib@openssh.com",
      "hmac-sha256-2@ssh.com,none", "hmac-sha256-2@ssh.com,zlib@openssh.com",
      "hmac-sha256@ssh.com,none", "hmac-sha256@ssh.com,zlib@openssh.com",
      "hmac-sha224@ssh.com,none", "hmac-sha224@ssh.com,zlib@openssh.com"})
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

  @ParameterizedTest
  @ValueSource(strings = {"com.jcraft.jsch.juz.Compression", "com.jcraft.jsch.jzlib.Compression"})
  public void testCompressionImpls(String impl) throws Exception {
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("compression.s2c", "zlib");
    session.setConfig("compression.c2s", "zlib");
    session.setConfig("zlib", impl);
    doSftp(session, true);

    String expectedImpl = String.format("zlib using %s", impl);
    String expectedS2C = "kex: server->client .* compression: zlib.*";
    String expectedC2S = "kex: client->server .* compression: zlib.*";
    checkLogs(expectedImpl);
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
    ssh.addIdentity(getResourceFile("docker/id_ed448"), getResourceFile("docker/id_ed448.pub"),
        null);
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private HostKey readHostKey(String fileName) throws Exception {
    List<String> lines = Files.readAllLines(Paths.get(fileName), UTF_8);
    String[] split = lines.get(0).split("\\s+");
    String hostname = String.format("[%s]:%d", sshd.getHost(), sshd.getFirstMappedPort());
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
    try {
      assertTrue(actualJsch.isPresent(), () -> "JSch: " + expected);
    } catch (AssertionError e) {
      printInfo();
      throw e;
    }
  }

  private String getResourceFile(String fileName) {
    return ResourceUtil.getResourceFile(getClass(), fileName);
  }
}
