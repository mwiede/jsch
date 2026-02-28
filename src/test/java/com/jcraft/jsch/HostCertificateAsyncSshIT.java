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
 * Integration tests for {@code ssh-ed448-cert-v01@openssh.com} host certificate validation using
 * AsyncSSH.
 *
 * These tests verify that JSch correctly validates a host certificate whose underlying key
 * algorithm is Ed448 ({@code ssh-ed448-cert-v01@openssh.com}). The certificate is signed by an
 * Ed25519 CA, so no Java 15+ requirement is imposed on the client side.
 *
 * The AsyncSSH server (Python) is used because it natively supports the full Ed448 certificate
 * workflow, unlike OpenSSH which may not expose Ed448 host certificate support on all platforms.
 *
 * @see HostCertificateIT for the equivalent tests using an OpenSSH server with RSA/ECDSA/Ed25519
 *      host certificates.
 * @see Algorithms2IT for the equivalent plain (non-certificate) Ed448 host key tests.
 */
@Testcontainers
public class HostCertificateAsyncSshIT {

  private static final int TIMEOUT = 5000;
  private static final String BASE = "certificates/asyncssh_host";

  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger =
      TestLoggerFactory.getTestLogger(HostCertificateAsyncSshIT.class);

  /**
   * AsyncSSH container configured to serve an Ed448 host certificate
   * ({@code ssh-ed448-cert-v01@openssh.com}). The certificate is signed by an Ed25519 CA whose
   * public key is in the client's {@code known_hosts} file with the {@code @cert-authority} marker.
   */
  @Container
  private static final GenericContainer<?> sshdContainer = new GenericContainer<>(
      new ImageFromDockerfile().withFileFromClasspath("Dockerfile", BASE + "/Dockerfile")
          .withFileFromClasspath("asyncsshd_cert.py", BASE + "/asyncsshd_cert.py")
          .withFileFromClasspath("ssh_host_ed448_key", BASE + "/ssh_host_ed448_key")
          .withFileFromClasspath("ssh_host_ed448_key-cert.pub",
              BASE + "/ssh_host_ed448_key-cert.pub")
          .withFileFromClasspath("id_ecdsa_nistp521.pub", BASE + "/id_ecdsa_nistp521.pub"))
      .withExposedPorts(22).waitingFor(Wait.forListeningPort());

  /**
   * Happy path: JSch connects successfully to a server presenting a valid
   * {@code ssh-ed448-cert-v01@openssh.com} certificate signed by a trusted CA.
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
    session.setConfig("server_host_key", "ssh-ed448-cert-v01@openssh.com");

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
    session.setConfig("server_host_key", "ssh-ed448-cert-v01@openssh.com");

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
