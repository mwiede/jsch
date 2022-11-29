package com.jcraft.jsch;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.jcraft.jsch.JSchTest.TestLogger;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

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
        Arguments.of("42 socket", "127.0.0.1", null, -1, "socket")// socket wo bind
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
}
