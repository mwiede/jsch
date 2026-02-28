package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jcraft.jsch.JSchTest.TestLogger;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

class SessionTest {

  static JSch jsch = new JSch();

  @ParameterizedTest
  @MethodSource("sshConfigs")
  void parseForwarding(String sshConfig, String expectedBindAddress, String expectedHost,
      int expectedHostPort, String expectedSocket) throws JSchException {
    final Session session = new Session(jsch, null, null, 0);
    final Session.Forwarding forwarding = session.parseForwarding(sshConfig);
    assertEquals(expectedBindAddress, forwarding.bind_address);
    assertEquals(42, forwarding.port);
    assertEquals(expectedHost, forwarding.host);
    assertEquals(expectedHostPort, forwarding.hostport);
    assertEquals(expectedSocket, forwarding.socketPath);
  }

  private static Stream<Arguments> sshConfigs() {
    return Stream.of(Arguments.of("bind_address:42:host:99", "bind_address", "host", 99, null), // colon
        Arguments.of("bind_address:42 host:99", "bind_address", "host", 99, null), // blank
        Arguments.of("42:host:99", "127.0.0.1", "host", 99, null), // colon wo bind
        Arguments.of("42 host:99", "127.0.0.1", "host", 99, null), // blank wo bind
        Arguments.of("localhost:42 host:99", "127.0.0.1", "host", 99, null), // blank
        Arguments.of(":42 host:99", "0.0.0.0", "host", 99, null), // bind is empty
        Arguments.of("*:42 host:99", "0.0.0.0", "host", 99, null), // bind is asterisk
        Arguments.of("bind_adress:42 socket", "bind_adress", null, -1, "socket"), // socket
        Arguments.of("42 socket", "127.0.0.1", null, -1, "socket") // socket wo bind
    );
  }

  @Test
  void getPubkeyAcceptedKeyTypes() throws JSchException {
    Session session = new Session(jsch, null, null, 0);
    session.setConfig("PubkeyAcceptedAlgorithms", "SessionTest111");
    assertEquals("SessionTest111", session.getConfig("PubkeyAcceptedKeyTypes"));
    assertEquals("SessionTest111", session.getConfig("PubkeyAcceptedAlgorithms"));
  }

  @Test
  void setPubkeyAcceptedKeyTypes() throws JSchException {
    Session session = new Session(jsch, null, null, 0);
    session.setConfig("PubkeyAcceptedKeyTypes", "SessionTest222");
    assertEquals("SessionTest222", session.getConfig("PubkeyAcceptedKeyTypes"));
    assertEquals("SessionTest222", session.getConfig("PubkeyAcceptedAlgorithms"));
  }

  @Test
  void checkLoggerFunctionality() throws Exception {
    Logger orgLogger = JSch.getLogger();
    try {
      JSch.setLogger(null);
      TestLogger staticLogger = new TestLogger();
      TestLogger jschInstanceLogger = new TestLogger();
      TestLogger sessionLogger = new TestLogger();

      Session session = new Session(jsch, null, null, 0);

      assertSame(JSch.DEVNULL, session.getLogger(), "DEVNULL logger expected after creation");

      JSch.setLogger(staticLogger);
      assertSame(staticLogger, session.getLogger(),
          "static logger expected after setting static logger");

      jsch.setInstanceLogger(jschInstanceLogger);
      assertSame(jschInstanceLogger, session.getLogger(),
          "static logger expected after setting instance logger");

      session.setLogger(sessionLogger);
      assertSame(sessionLogger, session.getLogger(),
          "static logger expected after setting session logger");
    } finally {
      JSch.setLogger(orgLogger);
    }
  }

  // ==================== Tests for CASignatureAlgorithms ====================

  /**
   * Tests that the default ca_signature_algorithms config matches OpenSSH 8.2+ defaults (excludes
   * ssh-rsa/SHA-1).
   */
  @Test
  void testDefaultCASignatureAlgorithms() {
    String defaultCaSigAlgs = JSch.getConfig("ca_signature_algorithms");
    assertTrue(defaultCaSigAlgs.contains("ssh-ed25519"), "Default should include ssh-ed25519");
    assertTrue(defaultCaSigAlgs.contains("ecdsa-sha2-nistp256"),
        "Default should include ecdsa-sha2-nistp256");
    assertTrue(defaultCaSigAlgs.contains("rsa-sha2-256"), "Default should include rsa-sha2-256");
    assertTrue(defaultCaSigAlgs.contains("rsa-sha2-512"), "Default should include rsa-sha2-512");
    // ssh-rsa (SHA-1) should NOT be in the default list (OpenSSH 8.2+ behavior)
    assertTrue(
        !defaultCaSigAlgs.contains(",ssh-rsa,") && !defaultCaSigAlgs.endsWith(",ssh-rsa")
            && !defaultCaSigAlgs.startsWith("ssh-rsa,") && !defaultCaSigAlgs.equals("ssh-rsa"),
        "Default should NOT include ssh-rsa (SHA-1)");
  }

  /**
   * Tests that checkCASignatureAlgorithm passes for algorithms in the allowed list.
   */
  @Test
  void testCheckCASignatureAlgorithm_allowedAlgorithm() throws JSchException {
    Session session = new Session(jsch, null, null, 0);
    // ecdsa-sha2-nistp256 is in the default ca_signature_algorithms
    assertDoesNotThrow(() -> session.checkCASignatureAlgorithm("ecdsa-sha2-nistp256"),
        "Algorithm in the allowed list should not throw");
  }

  /**
   * Tests that checkCASignatureAlgorithm throws for algorithms not in the allowed list.
   */
  @Test
  void testCheckCASignatureAlgorithm_disallowedAlgorithm() throws JSchException {
    Session session = new Session(jsch, null, null, 0);
    // ssh-rsa (SHA-1) is NOT in the default ca_signature_algorithms
    JSchException exception =
        assertThrows(JSchException.class, () -> session.checkCASignatureAlgorithm("ssh-rsa"),
            "Algorithm not in the allowed list should throw JSchException");
    assertTrue(exception.getMessage().contains("not in the allowed ca_signature_algorithms"),
        "Exception message should indicate algorithm not allowed");
  }

  /**
   * Tests that checkCASignatureAlgorithm can be configured to allow ssh-rsa.
   */
  @Test
  void testCheckCASignatureAlgorithm_customConfig() throws JSchException {
    Session session = new Session(jsch, null, null, 0);
    // Configure to allow ssh-rsa
    session.setConfig("ca_signature_algorithms", "ssh-rsa,rsa-sha2-256,rsa-sha2-512");
    assertDoesNotThrow(() -> session.checkCASignatureAlgorithm("ssh-rsa"),
        "ssh-rsa should be allowed when explicitly configured");
  }

  /**
   * Tests that checkCASignatureAlgorithm allows all algorithms when config is empty.
   */
  @Test
  void testCheckCASignatureAlgorithm_emptyConfig() throws JSchException {
    Session session = new Session(jsch, null, null, 0);
    session.setConfig("ca_signature_algorithms", "");
    // With empty config, no restriction on which algorithms are allowed
    assertDoesNotThrow(() -> session.checkCASignatureAlgorithm("ecdsa-sha2-nistp256"),
        "Algorithm should be allowed when config is empty");
  }
}
