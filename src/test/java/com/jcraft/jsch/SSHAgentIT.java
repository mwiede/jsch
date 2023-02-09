package com.jcraft.jsch;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.condition.JRE.JAVA_16;
import static org.junit.jupiter.api.condition.OS.LINUX;
import static org.testcontainers.containers.BindMode.READ_WRITE;

import com.github.valfirst.slf4jtest.LoggingEvent;
import com.github.valfirst.slf4jtest.TestLogger;
import com.github.valfirst.slf4jtest.TestLoggerFactory;
import com.sun.jna.platform.unix.LibC;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@EnabledOnOs(LINUX)
@Testcontainers
public class SSHAgentIT {

  private static final int timeout = 2000;
  private static final DigestUtils sha256sum = new DigestUtils(DigestUtils.getSha256Digest());
  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger = TestLoggerFactory.getTestLogger(SSHAgentIT.class);
  private static final TestLogger sshAgentLogger =
      TestLoggerFactory.getTestLogger(AgentProxy.class);
  @TempDir
  public static Path tmpDir;
  private static String testuid;
  private static String testgid;
  private static Path sshAgentSock;

  private Path in;
  private Path out;
  private String hash;
  private Slf4jLogConsumer sshdLogConsumer;
  private Slf4jLogConsumer sshAgentLogConsumer;

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

  @Container
  public GenericContainer<?> sshAgent = new GenericContainer<>(
      new ImageFromDockerfile().withBuildArg("testuid", testuid).withBuildArg("testgid", testgid)
          .withFileFromClasspath("Dockerfile", "docker/Dockerfile.sshagent"))
      .withFileSystemBind(sshAgentSock.getParent().toString(), "/testuser", READ_WRITE);

  @BeforeAll
  public static void beforeAll() throws IOException {
    JSch.setLogger(new Slf4jLogger());
    LibC libc = LibC.INSTANCE;
    testuid = Integer.toString(libc.getuid());
    testgid = Integer.toString(libc.getgid());
    Path temp = Files.createTempDirectory(tmpDir, "sshagent");
    sshAgentSock = temp.resolve("sock");
  }

  @BeforeEach
  public void beforeEach() throws IOException {
    if (sshdLogConsumer == null) {
      sshdLogConsumer = new Slf4jLogConsumer(sshdLogger);
      sshd.followOutput(sshdLogConsumer);
    }

    if (sshAgentLogConsumer == null) {
      sshAgentLogConsumer = new Slf4jLogConsumer(sshAgentLogger);
      sshAgent.followOutput(sshAgentLogConsumer);
    }

    Path temp = Files.createTempDirectory(tmpDir, "sshd");
    in = temp.resolve("in");
    out = temp.resolve("out");
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
    sshAgentLogger.clearAll();
  }

  @AfterEach
  public void afterEach() {
    try {
      Files.deleteIfExists(sshAgentSock);
    } catch (IOException ignore) {
    }

    try {
      Files.deleteIfExists(out);
    } catch (IOException ignore) {
    }

    try {
      Files.deleteIfExists(in);
    } catch (IOException ignore) {
    }

    try {
      Files.deleteIfExists(in.getParent());
    } catch (IOException ignore) {
    }
  }

  @AfterAll
  public static void afterAll() {
    JSch.setLogger(null);
    jschLogger.clearAll();
    sshdLogger.clearAll();
    sshAgentLogger.clearAll();

    try {
      Files.deleteIfExists(sshAgentSock.getParent());
    } catch (IOException ignore) {
    }
  }

  @Test
  public void testEd25519JUnixSocketFactory() throws Exception {
    JSch ssh = createEd25519Identity(new JUnixSocketFactory());
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ssh-ed25519");
    doSftp(session, true);
  }

  @Test
  public void testECDSA521JUnixSocketFactory() throws Exception {
    JSch ssh = createECDSA521Identity(new JUnixSocketFactory());
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ecdsa-sha2-nistp521");
    doSftp(session, true);
  }

  @Test
  public void testECDSA384JUnixSocketFactory() throws Exception {
    JSch ssh = createECDSA384Identity(new JUnixSocketFactory());
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ecdsa-sha2-nistp384");
    doSftp(session, true);
  }

  @Test
  public void testECDSA256JUnixSocketFactory() throws Exception {
    JSch ssh = createECDSA256Identity(new JUnixSocketFactory());
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ecdsa-sha2-nistp256");
    doSftp(session, true);
  }

  @ParameterizedTest
  @ValueSource(strings = {"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"})
  public void testRSAJUnixSocketFactory(String keyType) throws Exception {
    JSch ssh = createRSAIdentity(new JUnixSocketFactory());
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", keyType);
    doSftp(session, true);
  }

  @Test
  public void testDSAJUnixSocketFactory() throws Exception {
    JSch ssh = createDSAIdentity(new JUnixSocketFactory());
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ssh-dss");
    doSftp(session, true);
  }

  @Test
  @EnabledForJreRange(min = JAVA_16)
  public void testEd25519UnixDomainSocketFactory() throws Exception {
    JSch ssh = createEd25519Identity(new UnixDomainSocketFactory());
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ssh-ed25519");
    doSftp(session, true);
  }

  @Test
  @EnabledForJreRange(min = JAVA_16)
  public void testECDSA521UnixDomainSocketFactory() throws Exception {
    JSch ssh = createECDSA521Identity(new UnixDomainSocketFactory());
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ecdsa-sha2-nistp521");
    doSftp(session, true);
  }

  @Test
  @EnabledForJreRange(min = JAVA_16)
  public void testECDSA384UnixDomainSocketFactory() throws Exception {
    JSch ssh = createECDSA384Identity(new UnixDomainSocketFactory());
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ecdsa-sha2-nistp384");
    doSftp(session, true);
  }

  @Test
  @EnabledForJreRange(min = JAVA_16)
  public void testECDSA256UnixDomainSocketFactory() throws Exception {
    JSch ssh = createECDSA256Identity(new UnixDomainSocketFactory());
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ecdsa-sha2-nistp256");
    doSftp(session, true);
  }

  @ParameterizedTest
  @ValueSource(strings = {"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"})
  @EnabledForJreRange(min = JAVA_16)
  public void testRSAUnixDomainSocketFactory(String keyType) throws Exception {
    JSch ssh = createRSAIdentity(new UnixDomainSocketFactory());
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", keyType);
    doSftp(session, true);
  }

  @Test
  @EnabledForJreRange(min = JAVA_16)
  public void testDSAUnixDomainSocketFactory() throws Exception {
    JSch ssh = createDSAIdentity(new UnixDomainSocketFactory());
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", "ssh-dss");
    doSftp(session, true);
  }

  private JSch createRSAIdentity(USocketFactory factory) throws Exception {
    IdentityRepository ir =
        new AgentIdentityRepository(new SSHAgentConnector(factory, sshAgentSock));
    assertTrue(ir.getIdentities().isEmpty(), "ssh-agent empty");

    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_rsa_key.pub"));
    JSch ssh = new JSch();
    ssh.setIdentityRepository(ir);
    ssh.addIdentity(getResourceFile("docker/id_rsa"), getResourceFile("docker/id_rsa.pub"), null);
    assertEquals(1, ir.getIdentities().size());
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private JSch createECDSA256Identity(USocketFactory factory) throws Exception {
    IdentityRepository ir =
        new AgentIdentityRepository(new SSHAgentConnector(factory, sshAgentSock));
    assertTrue(ir.getIdentities().isEmpty(), "ssh-agent empty");

    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_rsa_key.pub"));
    JSch ssh = new JSch();
    ssh.setIdentityRepository(ir);
    ssh.addIdentity(getResourceFile("docker/id_ecdsa256"),
        getResourceFile("docker/id_ecdsa256.pub"), null);
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private JSch createECDSA384Identity(USocketFactory factory) throws Exception {
    IdentityRepository ir =
        new AgentIdentityRepository(new SSHAgentConnector(factory, sshAgentSock));
    assertTrue(ir.getIdentities().isEmpty(), "ssh-agent empty");

    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_rsa_key.pub"));
    JSch ssh = new JSch();
    ssh.setIdentityRepository(ir);
    ssh.addIdentity(getResourceFile("docker/id_ecdsa384"),
        getResourceFile("docker/id_ecdsa384.pub"), null);
    assertEquals(1, ir.getIdentities().size());
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private JSch createECDSA521Identity(USocketFactory factory) throws Exception {
    IdentityRepository ir =
        new AgentIdentityRepository(new SSHAgentConnector(factory, sshAgentSock));
    assertTrue(ir.getIdentities().isEmpty(), "ssh-agent empty");

    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_rsa_key.pub"));
    JSch ssh = new JSch();
    ssh.setIdentityRepository(ir);
    ssh.addIdentity(getResourceFile("docker/id_ecdsa521"),
        getResourceFile("docker/id_ecdsa521.pub"), null);
    assertEquals(1, ir.getIdentities().size());
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private JSch createDSAIdentity(USocketFactory factory) throws Exception {
    IdentityRepository ir =
        new AgentIdentityRepository(new SSHAgentConnector(factory, sshAgentSock));
    assertTrue(ir.getIdentities().isEmpty(), "ssh-agent empty");

    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_rsa_key.pub"));
    JSch ssh = new JSch();
    ssh.setIdentityRepository(ir);
    ssh.addIdentity(getResourceFile("docker/id_dsa"), getResourceFile("docker/id_dsa.pub"), null);
    assertEquals(1, ir.getIdentities().size());
    ssh.getHostKeyRepository().add(hostKey, null);
    return ssh;
  }

  private JSch createEd25519Identity(USocketFactory factory) throws Exception {
    IdentityRepository ir =
        new AgentIdentityRepository(new SSHAgentConnector(factory, sshAgentSock));
    assertTrue(ir.getIdentities().isEmpty(), "ssh-agent empty");

    HostKey hostKey = readHostKey(getResourceFile("docker/ssh_host_rsa_key.pub"));
    JSch ssh = new JSch();
    ssh.setIdentityRepository(ir);
    ssh.addIdentity(getResourceFile("docker/id_ed25519"), getResourceFile("docker/id_ed25519.pub"),
        null);
    assertEquals(1, ir.getIdentities().size());
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
    sshAgentLogger.getAllLoggingEvents().stream().map(LoggingEvent::getFormattedMessage)
        .forEach(System.out::println);
    System.out.println("");
    System.out.println("");
    System.out.println("");
  }

  private String getResourceFile(String fileName) {
    return ResourceUtil.getResourceFile(getClass(), fileName);
  }
}
