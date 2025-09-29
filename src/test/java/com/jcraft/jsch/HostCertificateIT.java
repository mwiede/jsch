package com.jcraft.jsch;

import com.github.valfirst.slf4jtest.LoggingEvent;
import com.github.valfirst.slf4jtest.TestLogger;
import com.github.valfirst.slf4jtest.TestLoggerFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Arrays;

import static com.jcraft.jsch.ResourceUtil.getResourceFile;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for SSH host certificate validation.
 * <p>
 * These tests leverage Testcontainers to spin up a dedicated SSH server in a Docker container,
 * configured with specific host keys and certificates. The primary goal is to verify JSch's ability
 * to validate server host keys signed by a Certificate Authority (CA) against a {@code known_hosts}
 * file.
 */

@Testcontainers
public class HostCertificateIT {

  /** Connection timeout in milliseconds. */
  private static final int TIMEOUT = 5000;
  /** Base resource folder for certificates and keys used in the tests. */
  private static final String CERTIFICATES_BASE_FOLDER = "certificates/host";
  /** Test logger for capturing JSch internal logs for debugging purposes. */
  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  /** Test logger for capturing SSH server logs (via a placeholder class). */
  private static final TestLogger sshdLogger =
      TestLoggerFactory.getTestLogger(UserCertAuthIT.class);

  /**
   * Defines and configures the SSH server Docker container using Testcontainers. The container is
   * built from a custom Dockerfile that:
   * <ul>
   * <li>Starts from a lightweight Alpine Linux image.</li>
   * <li>Installs an OpenSSH server.</li>
   * <li>Creates a test user ('luigi').</li>
   * <li>Copies all necessary configuration, keys, and certificates from the test resources.</li>
   * <li>Starts the SSH server via a custom entrypoint script.</li>
   * </ul>
   */
  @Container
  private GenericContainer<?> sshdContainer =
      new GenericContainer<>(new ImageFromDockerfile("jsch_host_key_test", false)
          .withDockerfileFromBuilder(builder -> builder.from("alpine:3.16")
              .run("apk add --update openssh openssh-server bash && " + "rm /var/cache/apk/*")
              .run("adduser -D luigi") // Add a user
              .run("echo 'luigi:passwordLuigi' | chpasswd") // Unlock the user
              .run("mkdir -p /home/luigi/.ssh").copy("sshd_config", "/etc/ssh/sshd_config")
              .copy("authorized_keys", "/home/luigi/.ssh/authorized_keys")
              .copy("entrypoint.sh", "/entrypoint.sh")
              .copy("ssh_host_rsa_key", "/etc/ssh/ssh_host_rsa_key")
              .copy("ssh_host_rsa_key-cert.pub", "/etc/ssh/ssh_host_rsa_key-cert.pub")
              .copy("ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ecdsa_key")
              .copy("ssh_host_ecdsa_key-cert.pub", "/etc/ssh/ssh_host_ecdsa_key-cert.pub")
              .copy("ssh_host_ed25519_key", "/etc/ssh/ssh_host_ed25519_key")
              .copy("ssh_host_ed25519_key-cert.pub", "/etc/ssh/ssh_host_ed25519_key-cert.pub")
              .entryPoint("/entrypoint.sh").build())
          .withFileFromClasspath("sshd_config", CERTIFICATES_BASE_FOLDER + "/sshd_config")
          .withFileFromClasspath("authorized_keys",
              CERTIFICATES_BASE_FOLDER + "/user_keys/id_ecdsa_nistp521.pub")
          .withFileFromClasspath("entrypoint.sh", CERTIFICATES_BASE_FOLDER + "/entrypoint.sh")
          .withFileFromClasspath("ssh_host_rsa_key", CERTIFICATES_BASE_FOLDER + "/ssh_host_rsa_key")
          .withFileFromClasspath("ssh_host_rsa_key-cert.pub",
              CERTIFICATES_BASE_FOLDER + "/ssh_host_rsa_key-cert.pub")
          .withFileFromClasspath("ssh_host_ecdsa_key",
              CERTIFICATES_BASE_FOLDER + "/ssh_host_ecdsa_key")
          .withFileFromClasspath("ssh_host_ecdsa_key-cert.pub",
              CERTIFICATES_BASE_FOLDER + "/ssh_host_ecdsa_key-cert.pub")
          .withFileFromClasspath("ssh_host_ed25519_key",
              CERTIFICATES_BASE_FOLDER + "/ssh_host_ed25519_key")
          .withFileFromClasspath("ssh_host_ed25519_key-cert.pub",
              CERTIFICATES_BASE_FOLDER + "/ssh_host_ed25519_key-cert.pub"))
          .withExposedPorts(22)
          .waitingFor(Wait.forLogMessage(".*Server listening on :: port 22.*", 1));


  /**
   * Provides a stream of server host key algorithms to be used in parameterized tests. Each string
   * corresponds to the {@code server_host_key} configuration option in JSch.
   *
   * @return An iterable of host key algorithm strings for test parameterization.
   */
  public static Iterable<? extends String> privateKeyParams() {
    return Arrays.asList("ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com",
        "ssh-rsa-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com");
  }

  /**
   * Tests the successful connection scenario where the server's host certificate is signed by a CA
   * that is trusted in the client's {@code known_hosts} file. This test is parameterized to run
   * against different host key algorithms.
   *
   * @param algorithm The server host key algorithm to test, provided by
   *        {@link #privateKeyParams()}.
   * @throws Exception if any error occurs during the test.
   */
  @MethodSource("privateKeyParams")
  @ParameterizedTest(name = "hostkey algorithm: {0}")
  public void hostKeyTestHappyPath(String algorithm) throws Exception {
    JSch ssh = new JSch();
    ssh.addIdentity(
        getResourceFile(this.getClass(), CERTIFICATES_BASE_FOLDER + "/user_keys/id_ecdsa_nistp521"),
        getResourceFile(this.getClass(),
            CERTIFICATES_BASE_FOLDER + "/user_keys/id_ecdsa_nistp521.pub"),
        null);

    ssh.setKnownHosts(getResourceFile(this.getClass(), "certificates/known_hosts"));
    Session session =
        ssh.getSession("luigi", sshdContainer.getHost(), sshdContainer.getFirstMappedPort());
    session.setConfig("enable_auth_none", "no");
    session.setConfig("StrictHostKeyChecking", "yes");
    session.setConfig("PreferredAuthentications", "publickey");
    session.setConfig("server_host_key", algorithm);
    assertDoesNotThrow(() -> {
      connectSftp(session);
    });
  }

  /**
   * Tests the failure scenario where the server's host certificate cannot be trusted. This test
   * verifies that a {@link JSchHostKeyException} is thrown, as expected when
   * {@code StrictHostKeyChecking} is enabled and the host key/certificate does not match any entry
   * in the {@code known_hosts} file.
   *
   * @param algorithm The server host key algorithm to test, provided by
   *        {@link #privateKeyParams()}.
   * @throws Exception if any error occurs during the test setup.
   */
  @MethodSource("privateKeyParams")
  @ParameterizedTest(name = "hostkey algorithm: {0}")
  public void hostKeyTestNotTrustedCA(String algorithm) throws Exception {
    JSch ssh = new JSch();

    ssh.addIdentity(
        getResourceFile(this.getClass(), CERTIFICATES_BASE_FOLDER + "/user_keys/id_ecdsa_nistp521"),
        getResourceFile(this.getClass(),
            CERTIFICATES_BASE_FOLDER + "/user_keys/id_ecdsa_nistp521.pub"),
        null);

    Session session = setup(ssh, algorithm);
    assertThrows(JSchHostKeyException.class, () -> {
      connectSftp(session);
    });
  }


  /**
   * Helper method to create and configure a JSch {@link Session} with common settings for the
   * tests.
   *
   * @param ssh The JSch instance.
   * @param algorithm The server host key algorithm to prefer.
   * @return A configured {@link Session} object.
   * @throws JSchException if there is an error creating the session.
   */
  private Session setup(JSch ssh, String algorithm) throws JSchException {
    Session session =
        ssh.getSession("luigi", sshdContainer.getHost(), sshdContainer.getFirstMappedPort());
    session.setConfig("enable_auth_none", "no");
    session.setConfig("StrictHostKeyChecking", "yes");
    session.setConfig("PreferredAuthentications", "publickey");
    session.setConfig("server_host_key", algorithm);
    return session;
  }

  /**
   * Establishes a session connection, opens an SFTP channel to verify connectivity, and then
   * cleanly disconnects. If any exception occurs, it prints diagnostic information before
   * re-throwing the exception.
   *
   * @param session The session to connect with.
   * @throws JSchException if a JSch-specific error occurs.
   */
  private void connectSftp(Session session) throws JSchException {
    try {
      session.setTimeout(TIMEOUT);
      session.connect();
      ChannelSftp sftp = (ChannelSftp) session.openChannel("sftp");
      sftp.connect(TIMEOUT);
      assertTrue(sftp.isConnected());
      sftp.disconnect();
      session.disconnect();
    } catch (Exception e) {
      printInfo();
      throw e;
    }
  }

  /**
   * A utility method for debugging. Prints all captured log events from both the JSch client and
   * the mock SSH server to the console.
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
