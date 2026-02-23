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
 * Integration tests for {@code ssh-ed448-cert-v01@openssh.com} user certificate authentication
 * using AsyncSSH.
 *
 *
 * These tests verify that JSch can authenticate to a server using an OpenSSH user certificate whose
 * underlying key algorithm is Ed448 ({@code ssh-ed448-cert-v01@openssh.com}). The certificate is
 * signed by an Ed25519 CA; the server trusts that CA via its {@code authorized_keys} file (using
 * the {@code cert-authority} option).
 *
 *
 * AsyncSSH is used because it natively supports the full Ed448 user-certificate workflow, including
 * parsing and verifying {@code ssh-ed448-cert-v01@openssh.com} user certificates.
 *
 * @see UserCertAuthIT for user certificate tests against a standard OpenSSH server.
 * @see Algorithms2IT for plain (non-certificate) Ed448 host-key tests using AsyncSSH.
 */
@Testcontainers
public class UserCertAuthAsyncSshIT {

  private static final int TIMEOUT = 5000;
  private static final String BASE = "certificates/asyncssh_user";

  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger =
      TestLoggerFactory.getTestLogger(UserCertAuthAsyncSshIT.class);

  /**
   * AsyncSSH container configured to accept user certificate authentication via a trusted CA.
   *
   * <p>
   * The server's {@code authorized_keys} file contains a {@code cert-authority} entry pointing to
   * the same Ed25519 CA that signed the Ed448 user certificate used by the client.
   */
  @Container
  private static final GenericContainer<?> sshdContainer = new GenericContainer<>(
      new ImageFromDockerfile().withFileFromClasspath("Dockerfile", BASE + "/Dockerfile")
          .withFileFromClasspath("asyncsshd_user_cert.py", BASE + "/asyncsshd_user_cert.py")
          .withFileFromClasspath("ssh_host_ed25519_key", BASE + "/ssh_host_ed25519_key")
          .withFileFromClasspath("authorized_keys", BASE + "/authorized_keys"))
      .withExposedPorts(22).waitingFor(Wait.forListeningPort());

  /**
   * Verifies that JSch can successfully authenticate using an Ed448 user certificate
   * ({@code ssh-ed448-cert-v01@openssh.com}) signed by a CA trusted by the server.
   */
  @Test
  public void userCertAuthEd448Test() throws Exception {
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile(this.getClass(), BASE + "/root_ed448_key"),
        getResourceFile(this.getClass(), BASE + "/root_ed448_key-cert.pub"), null);

    Session session =
        ssh.getSession("root", sshdContainer.getHost(), sshdContainer.getFirstMappedPort());
    session.setConfig("StrictHostKeyChecking", "no");
    session.setConfig("PreferredAuthentications", "publickey");
    session.setConfig("PubkeyAcceptedAlgorithms", "ssh-ed448-cert-v01@openssh.com,ssh-ed448");
    // Use BouncyCastle Ed448 implementation (available on all Java versions)
    session.setConfig("keypairgen.eddsa", "com.jcraft.jsch.bc.KeyPairGenEdDSA");
    session.setConfig("ssh-ed448", "com.jcraft.jsch.bc.SignatureEd448");

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
