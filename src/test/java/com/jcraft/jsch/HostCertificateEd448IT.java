package com.jcraft.jsch;

import static com.jcraft.jsch.ResourceUtil.getResourceFile;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.condition.JRE.JAVA_15;

import com.github.valfirst.slf4jtest.LoggingEvent;
import com.github.valfirst.slf4jtest.TestLogger;
import com.github.valfirst.slf4jtest.TestLoggerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
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
 * Ed25519 CA, so no Java 15+ requirement is imposed on the client side for CA signature
 * verification.
 *
 * Each test scenario is run against both the native Java 15+ and Bouncy Castle implementations of
 * Ed448, as well as with the default (auto-detected) implementation, following the same pattern as
 * {@link Algorithms2IT#testJava15Ed448()}, {@link Algorithms2IT#testBCEd448()} and
 * {@link Algorithms2IT#testEd448()}.
 *
 * @see HostCertificateIT for the equivalent tests using an OpenSSH server with RSA/ECDSA/Ed25519
 *      host certificates.
 * @see Algorithms2IT for the equivalent plain (non-certificate) Ed448 host key tests.
 */
@Testcontainers
public class HostCertificateEd448IT {

  private static final int TIMEOUT = 5000;
  private static final String BASE = "certificates/asyncssh_host";

  private static final TestLogger jschLogger = TestLoggerFactory.getTestLogger(JSch.class);
  private static final TestLogger sshdLogger =
      TestLoggerFactory.getTestLogger(HostCertificateEd448IT.class);

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

  // ==================== Happy path tests ====================

  /**
   * Happy path using the native Java 15+ Ed448 implementation.
   */
  @Test
  @EnabledForJreRange(min = JAVA_15)
  public void testJava15Ed448HappyPath() throws Exception {
    Session session = createHappyPathSession();
    session.setConfig("keypairgen.eddsa", "com.jcraft.jsch.jce.KeyPairGenEdDSA");
    session.setConfig("ssh-ed448", "com.jcraft.jsch.jce.SignatureEd448");
    assertDoesNotThrow(() -> connectSftp(session));
  }

  /**
   * Happy path using the Bouncy Castle Ed448 implementation.
   */
  @Test
  public void testBCEd448HappyPath() throws Exception {
    Session session = createHappyPathSession();
    session.setConfig("keypairgen.eddsa", "com.jcraft.jsch.bc.KeyPairGenEdDSA");
    session.setConfig("ssh-ed448", "com.jcraft.jsch.bc.SignatureEd448");
    assertDoesNotThrow(() -> connectSftp(session));
  }

  /**
   * Happy path using the default (auto-detected) Ed448 implementation.
   */
  @Test
  public void testEd448HappyPath() throws Exception {
    Session session = createHappyPathSession();
    assertDoesNotThrow(() -> connectSftp(session));
  }

  // ==================== Untrusted CA tests ====================

  /**
   * Failure path using the native Java 15+ Ed448 implementation: JSch rejects the connection when
   * the server's certificate CA is not present in the client's {@code known_hosts} file.
   */
  @Test
  @EnabledForJreRange(min = JAVA_15)
  public void testJava15Ed448NotTrustedCA() throws Exception {
    Session session = createNotTrustedCASession();
    session.setConfig("keypairgen.eddsa", "com.jcraft.jsch.jce.KeyPairGenEdDSA");
    session.setConfig("ssh-ed448", "com.jcraft.jsch.jce.SignatureEd448");
    assertThrows(JSchHostKeyException.class, () -> connectSftp(session));
  }

  /**
   * Failure path using the Bouncy Castle Ed448 implementation: JSch rejects the connection when the
   * server's certificate CA is not present in the client's {@code known_hosts} file.
   */
  @Test
  public void testBCEd448NotTrustedCA() throws Exception {
    Session session = createNotTrustedCASession();
    session.setConfig("keypairgen.eddsa", "com.jcraft.jsch.bc.KeyPairGenEdDSA");
    session.setConfig("ssh-ed448", "com.jcraft.jsch.bc.SignatureEd448");
    assertThrows(JSchHostKeyException.class, () -> connectSftp(session));
  }

  /**
   * Failure path using the default (auto-detected) Ed448 implementation: JSch rejects the
   * connection when the server's certificate CA is not present in the client's {@code known_hosts}
   * file.
   */
  @Test
  public void testEd448NotTrustedCA() throws Exception {
    Session session = createNotTrustedCASession();
    assertThrows(JSchHostKeyException.class, () -> connectSftp(session));
  }

  // ==================== Helper methods ====================

  private Session createHappyPathSession() throws Exception {
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile(this.getClass(), BASE + "/id_ecdsa_nistp521"),
        getResourceFile(this.getClass(), BASE + "/id_ecdsa_nistp521.pub"), null);
    ssh.setKnownHosts(getResourceFile(this.getClass(), BASE + "/known_hosts"));
    return createSession(ssh);
  }

  private Session createNotTrustedCASession() throws Exception {
    JSch ssh = new JSch();
    ssh.addIdentity(getResourceFile(this.getClass(), BASE + "/id_ecdsa_nistp521"),
        getResourceFile(this.getClass(), BASE + "/id_ecdsa_nistp521.pub"), null);
    // no known_hosts set → CA not trusted
    return createSession(ssh);
  }

  private Session createSession(JSch ssh) throws JSchException {
    Session session =
        ssh.getSession("root", sshdContainer.getHost(), sshdContainer.getFirstMappedPort());
    session.setConfig("enable_auth_none", "no");
    session.setConfig("StrictHostKeyChecking", "yes");
    session.setConfig("PreferredAuthentications", "publickey");
    session.setConfig("server_host_key", "ssh-ed448-cert-v01@openssh.com");
    return session;
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
