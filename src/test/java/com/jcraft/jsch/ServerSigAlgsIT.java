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
import java.util.Optional;
import java.util.Random;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
public class ServerSigAlgsIT {

  private static final int timeout = 2000;
  private static final DigestUtils sha256sum = new DigestUtils(DigestUtils.getSha256Digest());
  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger =
      TestLoggerFactory.getTestLogger(ServerSigAlgsIT.class);

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

  @Test
  public void testServerSigAlgs() throws Exception {
    String algos =
        "ssh-rsa-sha512@ssh.com,ssh-rsa-sha384@ssh.com,ssh-rsa-sha256@ssh.com,ssh-rsa-sha224@ssh.com,rsa-sha2-512,rsa-sha2-256,ssh-rsa";
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("PubkeyAcceptedAlgorithms", algos);
    session.setConfig("server_host_key", algos);
    doSftp(session, true);

    String expectedKex = "kex: host key algorithm: rsa-sha2-512";
    String expectedExtInfo = "SSH_MSG_EXT_INFO received";
    String expectedServerSigAlgs =
        "server-sig-algs=<ssh-ed25519,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521>";
    String expectedPubkeysKnown =
        "PubkeyAcceptedAlgorithms in server-sig-algs = \\[rsa-sha2-512, rsa-sha2-256, ssh-rsa\\]";
    String expectedPubkeysUnknown =
        "PubkeyAcceptedAlgorithms not in server-sig-algs = \\[ssh-rsa-sha512@ssh.com, ssh-rsa-sha384@ssh.com, ssh-rsa-sha256@ssh.com, ssh-rsa-sha224@ssh.com\\]";
    String expectedPreauth = "rsa-sha2-512 preauth success";
    String expectedAuth = "rsa-sha2-512 auth success";
    checkLogs(expectedKex);
    checkLogs(expectedExtInfo);
    checkLogs(expectedServerSigAlgs);
    checkLogs(expectedPubkeysKnown);
    checkLogs(expectedPubkeysUnknown);
    checkLogs(expectedPreauth);
    checkLogs(expectedAuth);
  }

  @Test
  public void testNoServerSigAlgs() throws Exception {
    String algos =
        "ssh-rsa-sha512@ssh.com,ssh-rsa-sha384@ssh.com,ssh-rsa-sha256@ssh.com,ssh-rsa-sha224@ssh.com,rsa-sha2-512,rsa-sha2-256,ssh-rsa";
    JSch ssh = createRSAIdentity();
    Session session = createSession(ssh);
    session.setConfig("enable_server_sig_algs", "no");
    session.setConfig("PubkeyAcceptedAlgorithms", algos);
    session.setConfig("server_host_key", algos);
    doSftp(session, true);

    String expectedKex = "kex: host key algorithm: rsa-sha2-512";
    String expectedPubkeysNoServerSigs =
        String.format("No server-sig-algs found, using PubkeyAcceptedAlgorithms = %s", algos);
    String expectedPreauthFail1 = "ssh-rsa-sha512@ssh.com preauth failure";
    String expectedPreauthFail2 = "ssh-rsa-sha384@ssh.com preauth failure";
    String expectedPreauthFail3 = "ssh-rsa-sha256@ssh.com preauth failure";
    String expectedPreauthFail4 = "ssh-rsa-sha224@ssh.com preauth failure";
    String expectedPreauth = "rsa-sha2-512 preauth success";
    String expectedAuth = "rsa-sha2-512 auth success";
    checkLogs(expectedKex);
    checkLogs(expectedPreauthFail1);
    checkLogs(expectedPreauthFail2);
    checkLogs(expectedPreauthFail3);
    checkLogs(expectedPreauthFail4);
    checkLogs(expectedPreauth);
    checkLogs(expectedAuth);
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
