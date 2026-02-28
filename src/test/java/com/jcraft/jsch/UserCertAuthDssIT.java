package com.jcraft.jsch;

import static com.jcraft.jsch.ResourceUtil.getResourceFile;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
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
 * Integration tests for {@code ssh-dss-cert-v01@openssh.com} user certificate authentication.
 *
 *
 * These tests verify that JSch can authenticate to a server using an OpenSSH user certificate whose
 * underlying key algorithm is DSA ({@code ssh-dss-cert-v01@openssh.com}). The server runs Alpine
 * 3.5 with OpenSSH 7.4 because DSA support was removed from OpenSSH 9.8+.
 *
 *
 * The DSA user certificate is signed by an Ed25519 CA; the server is configured with
 * {@code TrustedUserCAKeys} pointing to that CA's public key.
 *
 * @see UserCertAuthIT for user certificate tests with modern key types on a current OpenSSH server.
 * @see HostCertificateDssIT for the equivalent host-certificate (not user-certificate) DSA tests.
 */
@Testcontainers
public class UserCertAuthDssIT {

  private static final int TIMEOUT = 5000;
  private static final String BASE = "certificates/dss_user";
  private static final String DSS_KEYS = "certificates/dss";

  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger =
      TestLoggerFactory.getTestLogger(UserCertAuthDssIT.class);

  /**
   * OpenSSH 7.4 (Alpine 3.5) container configured to accept DSA user certificate authentication.
   *
   * <p>
   * The server uses {@code TrustedUserCAKeys} with the Ed25519 CA that signed the DSA user
   * certificate. An older OpenSSH image is used intentionally because DSA support was removed from
   * OpenSSH 9.8.
   */
  @Container
  private static final GenericContainer<?> sshdContainer = new GenericContainer<>(
      new ImageFromDockerfile().withFileFromClasspath("Dockerfile", BASE + "/Dockerfile")
          .withFileFromClasspath("entrypoint.sh", BASE + "/entrypoint.sh")
          .withFileFromClasspath("sshd_config", BASE + "/sshd_config")
          .withFileFromClasspath("ca_jsch_key.pub", BASE + "/ca_jsch_key.pub"))
      .withExposedPorts(22).waitingFor(Wait.forLogMessage(".*Server listening on.*port 22.*", 1));

  /**
   * Verifies that JSch can successfully authenticate using a DSA user certificate
   * ({@code ssh-dss-cert-v01@openssh.com}) signed by a CA trusted by the server.
   */
  @Test
  public void userCertAuthDssTest() throws Exception {
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile(this.getClass(), DSS_KEYS + "/root_dsa_key"),
        getResourceFile(this.getClass(), DSS_KEYS + "/root_dsa_key-cert.pub"), null);

    Session session =
        ssh.getSession("root", sshdContainer.getHost(), sshdContainer.getFirstMappedPort());
    session.setConfig("StrictHostKeyChecking", "no");
    session.setConfig("PreferredAuthentications", "publickey");
    session.setConfig("PubkeyAcceptedAlgorithms",
        "ssh-dss-cert-v01@openssh.com,ssh-dss,ssh-ed25519,ecdsa-sha2-nistp256,"
            + "ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256");

    assertDoesNotThrow(() -> connectSftp(session));
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
