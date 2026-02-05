package com.jcraft.jsch;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import com.github.valfirst.slf4jtest.LoggingEvent;
import com.github.valfirst.slf4jtest.TestLogger;
import com.github.valfirst.slf4jtest.TestLoggerFactory;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;


/**
 * Integrated Test (IT) class to verify the JSch public key authentication mechanism using **OpenSSH
 * user certificates** against a Testcontainers-managed SSHD (SSH daemon) instance.
 * <p>
 * This test suite ensures that **JSch can successfully establish an SFTP connection** when
 * configured with various types of certified user keys (e.g., RSA, ECDSA, Ed25519). The container
 * is configured to trust the certificate authority (CA) key that signed the user certificates being
 * tested.
 */
@Testcontainers
public class UserCertAuthIT {
  /**
   * Standard SLF4J logger for this test class.
   */
  private static final Logger logger = LoggerFactory.getLogger(UserCertAuthIT.class);
  /**
   * Timeout value (in milliseconds) for session and channel connections.
   */
  private static final int timeout = 5000;
  /**
   * Utility for generating SHA-256 digests.
   */
  private static final DigestUtils sha256sum = new DigestUtils(DigestUtils.getSha256Digest());
  /**
   * Test logger for capturing JSch internal logging output.
   */
  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  /**
   * Test logger for capturing the logging output of this test class (the SSHD setup).
   */
  private static final TestLogger sshdLogger =
      TestLoggerFactory.getTestLogger(UserCertAuthIT.class);
  /**
   * The Testcontainers instance for the SSHD server.
   * <p>
   * The container is built from a Dockerfile and configured with:
   * <ul>
   * <li>A host RSA key (`ssh_host_rsa_key`).</li>
   * <li>A host certificate (`ssh_host_rsa_key-cert.pub`).</li>
   * <li>A Certificate Authority (CA) public key (`ca_jsch_key.pub`) to validate user
   * certificates.</li>
   * <li>An SSH configuration file (`sshd_config`).</li>
   * </ul>
   */
  @Container
  public GenericContainer<?> sshd = new GenericContainer<>(new ImageFromDockerfile()
      .withFileFromClasspath("ssh_host_rsa_key", "certificates/docker/ssh_host_rsa_key")
      // .withFileFromClasspath("ssh_host_rsa_key.pub", "certificates/docker/ssh_host_rsa_key.pub")
      .withFileFromClasspath("ssh_host_rsa_key-cert.pub",
          "certificates/docker/ssh_host_rsa_key-cert.pub")
      .withFileFromClasspath("ca_jsch_key.pub", "certificates/ca/ca_jsch_key.pub")
      .withFileFromClasspath("sshd_config", "certificates/docker/sshd_config")
      .withFileFromClasspath("Dockerfile", "certificates/docker/Dockerfile")).withExposedPorts(22)
      .waitingFor(Wait.forLogMessage(".*Server listening on :: port 22.*", 1));

  /**
   * Provides the list of private key parameters used for the parameterized test.
   * <p>
   * The keys represent various supported algorithms for user certificates.
   *
   * @return An {@code Iterable} of strings, each representing a private key file path prefix (e.g.,
   *         "ecdsa_p256/root_ecdsa_sha2_nistp256_key").
   */
  public static Iterable<? extends String> privateKeyParams() {
    return Arrays.asList(
        // disable dss because dsa algorithm is deprecated and removed by openssh server
        /* "dss/root_dsa_key", */
        "ecdsa_p256/root_ecdsa_sha2_nistp256_key", "ecdsa_p384/root_ecdsa-sha2-nistp384_key",
        "ecdsa_p521/root_ecdsa_sha2_nistp521_key", "ed25519/root_ed25519_key", "rsa/root_rsa_key");
  }

  /**
   * Tests JSch's ability to perform public key authentication using OpenSSH user certificates for
   * various key types.
   * <p>
   * The test adds the private key and its corresponding certificate (`-cert.pub`) to JSch and
   * attempts an SFTP connection to the Testcontainers-managed SSHD.
   *
   * @param privateKey The path prefix to the private key and certificate files (from the test
   *        resource directory).
   * @throws Exception if any error occurs during key reading, session setup, or connection.
   */
  @MethodSource("privateKeyParams")
  @ParameterizedTest(name = "key: {0}, cert: {0}-cert.pub")
  public void opensshCertificateParserTest(String privateKey) throws Exception {
    HostKey hostKey = readHostKey(
        ResourceUtil.getResourceFile(this.getClass(), "certificates/docker/ssh_host_rsa_key.pub"));
    JSch ssh = new JSch();
    ssh.addIdentity(ResourceUtil.getResourceFile(this.getClass(), "certificates/" + privateKey),
        ResourceUtil.getResourceFile(this.getClass(), "certificates/" + privateKey + "-cert.pub"),
        null);
    ssh.getHostKeyRepository().add(hostKey, null);

    Session session = ssh.getSession("root", sshd.getHost(), sshd.getFirstMappedPort());
    session.setConfig("enable_auth_none", "yes");
    session.setConfig("StrictHostKeyChecking", "no");
    session.setConfig("PreferredAuthentications", "publickey");
    // Include ssh-rsa-cert-v01@openssh.com for RSA certificate test (not in defaults per OpenSSH)
    session.setConfig("PubkeyAcceptedAlgorithms",
        "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256");
    session.setConfig("server_host_key",
        "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256");
    doSftp(session);
  }

  /**
   * Reads a public key file and constructs a {@link HostKey} object.
   * <p>
   * This method simulates how a known host entry might be created, but uses hardcoded placeholder
   * values for hostname and port in the constructed {@code HostKey}.
   *
   * @param fileName The absolute path to the public key file (e.g., {@code ssh_host_rsa_key.pub}).
   * @return A {@link HostKey} instance representing the key.
   * @throws Exception if the file cannot be read or the key content is malformed.
   */
  private HostKey readHostKey(String fileName) throws Exception {
    List<String> lines = Files.readAllLines(Paths.get(fileName), StandardCharsets.UTF_8);
    String[] split = lines.get(0).split("\\s+");
    String hostname = String.format(Locale.ROOT, "[%s]:%d", "localhost", 2222);
    return new HostKey(hostname, Base64.getDecoder().decode(split[1]));
  }

  /**
   * Connects the provided {@link Session} and attempts to perform a simple SFTP operation.
   * <p>
   * This method wraps the connection and SFTP channel creation in an {@code assertDoesNotThrow} to
   * ensure the entire process, including authentication, completes successfully.
   *
   * @param session The configured JSch session to connect.
   * @throws Exception if connection or SFTP channel setup fails.
   */
  private void doSftp(Session session) throws Exception {
    Assertions.assertDoesNotThrow(() -> {
      try {
        session.setTimeout(timeout);
        session.connect();
        ChannelSftp sftp = (ChannelSftp) session.openChannel("sftp");
        sftp.connect(timeout);
        Assertions.assertTrue(sftp.isConnected());
        sftp.disconnect();
        session.disconnect();
      } catch (Exception e) {
        printInfo();
        throw e;
      }
    });
  }

  /**
   * Prints all captured logging events from the JSch and SSHD test loggers to the standard output
   * for debugging purposes, primarily on test failure.
   */
  private void printInfo() {
    jschLogger.getAllLoggingEvents().stream().map(LoggingEvent::getFormattedMessage)
        .forEach(System.out::println);
    sshdLogger.getAllLoggingEvents().stream().map(LoggingEvent::getFormattedMessage)
        .forEach(System.out::println);
    System.out.println("");
    System.out.println("");
    System.out.println("");
  }
}
