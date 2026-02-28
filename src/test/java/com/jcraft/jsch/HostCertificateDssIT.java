package com.jcraft.jsch;

import static com.jcraft.jsch.ResourceUtil.getResourceFile;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.valfirst.slf4jtest.LoggingEvent;
import com.github.valfirst.slf4jtest.TestLogger;
import com.github.valfirst.slf4jtest.TestLoggerFactory;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Integration tests for {@code ssh-dss-cert-v01@openssh.com} host certificate validation.
 *
 * These tests verify that JSch correctly validates a host certificate whose underlying key
 * algorithm is DSA ({@code ssh-dss-cert-v01@openssh.com}). The server runs Alpine 3.5 with OpenSSH
 * 7.4, which is required because modern OpenSSH (9.8+) removed DSA support.
 *
 *
 * The DSA certificate is signed by an Ed25519 CA, so the client-side CA signature verification does
 * not require any additional JVM configuration.
 *
 *
 * @see HostCertificateIT for the equivalent tests using RSA/ECDSA/Ed25519 host certificates.
 */
@Testcontainers
public class HostCertificateDssIT {

  private static final int TIMEOUT = 5000;
  private static final String BASE = "certificates/dss_host";

  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger =
      TestLoggerFactory.getTestLogger(HostCertificateDssIT.class);

  /**
   * OpenSSH 7.4 (Alpine 3.5) container configured to serve a DSA host certificate
   * ({@code ssh-dss-cert-v01@openssh.com}). The certificate is signed by an Ed25519 CA whose public
   * key is in the client's {@code known_hosts} file with the {@code @cert-authority} marker.
   * <p>
   * An older OpenSSH image is intentionally used because DSA support was removed from OpenSSH 9.8.
   * </p>
   */
  @Container
  private static final GenericContainer<?> sshdContainer = new GenericContainer<>(
      new ImageFromDockerfile().withFileFromClasspath("Dockerfile", BASE + "/Dockerfile")
          .withFileFromClasspath("entrypoint.sh", BASE + "/entrypoint.sh")
          .withFileFromClasspath("sshd_config", BASE + "/sshd_config")
          .withFileFromClasspath("ssh_host_dsa_key", BASE + "/ssh_host_dsa_key")
          .withFileFromClasspath("ssh_host_dsa_key-cert.pub", BASE + "/ssh_host_dsa_key-cert.pub")
          .withFileFromClasspath("id_ecdsa_nistp521.pub", BASE + "/id_ecdsa_nistp521.pub"))
      .withExposedPorts(22).waitingFor(Wait.forListeningPort());

  /**
   * Happy path: JSch connects successfully to a server presenting a valid
   * {@code ssh-dss-cert-v01@openssh.com} certificate signed by a trusted CA.
   */
  @Test
  public void hostKeyTestHappyPath() throws Exception {
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile(this.getClass(), BASE + "/id_ecdsa_nistp521"),
        getResourceFile(this.getClass(), BASE + "/id_ecdsa_nistp521.pub"), null);
    ssh.setKnownHosts(getResourceFile(this.getClass(), BASE + "/known_hosts"));

    Session session =
        ssh.getSession("root", sshdContainer.getHost(), sshdContainer.getFirstMappedPort());
    session.setConfig("enable_auth_none", "no");
    session.setConfig("StrictHostKeyChecking", "yes");
    session.setConfig("PreferredAuthentications", "publickey");
    session.setConfig("server_host_key", "ssh-dss-cert-v01@openssh.com");

    assertDoesNotThrow(() -> connectSftp(session));
  }

  /**
   * Failure path: JSch rejects a connection when the server's certificate CA is not present in the
   * client's {@code known_hosts} file (empty known_hosts simulates an untrusted CA).
   */
  @Test
  public void hostKeyTestNotTrustedCA() throws Exception {
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile(this.getClass(), BASE + "/id_ecdsa_nistp521"),
        getResourceFile(this.getClass(), BASE + "/id_ecdsa_nistp521.pub"), null);
    // no known_hosts set → CA not trusted

    Session session =
        ssh.getSession("root", sshdContainer.getHost(), sshdContainer.getFirstMappedPort());
    session.setConfig("enable_auth_none", "no");
    session.setConfig("StrictHostKeyChecking", "yes");
    session.setConfig("PreferredAuthentications", "publickey");
    session.setConfig("server_host_key", "ssh-dss-cert-v01@openssh.com");

    assertThrows(JSchHostKeyException.class, () -> connectSftp(session));
  }

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

  private void printInfo() {
    jschLogger.getAllLoggingEvents().stream().map(LoggingEvent::getFormattedMessage)
        .forEach(System.out::println);
    sshdLogger.getAllLoggingEvents().stream().map(LoggingEvent::getFormattedMessage)
        .forEach(System.out::println);
  }
}
