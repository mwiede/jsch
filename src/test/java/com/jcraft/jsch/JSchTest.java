package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

class JSchTest {

  @BeforeEach
  void resetJsch() {
    JSch.setLogger(null);
  }

  @Test
  void getPubkeyAcceptedKeyTypes() throws JSchException {
    JSch.setConfig("PubkeyAcceptedAlgorithms", "JSchTest111");
    assertEquals("JSchTest111", JSch.getConfig("PubkeyAcceptedKeyTypes"));
    assertEquals("JSchTest111", JSch.getConfig("PubkeyAcceptedAlgorithms"));
  }

  @Test
  void setPubkeyAcceptedKeyTypes() throws JSchException {
    JSch.setConfig("PubkeyAcceptedKeyTypes", "JSchTest222");
    assertEquals("JSchTest222", JSch.getConfig("PubkeyAcceptedKeyTypes"));
    assertEquals("JSchTest222", JSch.getConfig("PubkeyAcceptedAlgorithms"));
  }

  @Test
  void setPubkeyAcceptedKeyTypesHashtable() {
    Map<String, String> newconf = new HashMap<>();
    newconf.put("PubkeyAcceptedKeyTypes", "JSchTest333");
    JSch.setConfig(newconf);
    assertEquals("JSchTest333", JSch.getConfig("PubkeyAcceptedKeyTypes"));
    assertEquals("JSchTest333", JSch.getConfig("PubkeyAcceptedAlgorithms"));
  }

  @Test
  void checkLoggerBehavior() throws Exception {
    assertSame(JSch.DEVNULL, JSch.logger, "initial static value of logger should be DEVNULL");

    JSch jsch = new JSch();
    assertSame(JSch.DEVNULL, jsch.getInstanceLogger(), "instance logger should be DEVNULL");

    TestLogger staticLogger = new TestLogger();
    TestLogger instanceLogger = new TestLogger();

    JSch.setLogger(staticLogger);
    assertSame(staticLogger, JSch.logger, "mismatch with static logger");
    assertSame(staticLogger, jsch.getInstanceLogger(), "instance should return static logger");

    jsch.setInstanceLogger(instanceLogger);
    assertSame(staticLogger, JSch.logger, "mismatch with static logger");
    assertSame(instanceLogger, jsch.getInstanceLogger(), "instance should return static logger");

    jsch.setInstanceLogger(null);
    assertSame(staticLogger, JSch.logger, "mismatch with static logger");
    assertSame(staticLogger, jsch.getInstanceLogger(), "instance should return static logger");

    JSch.setLogger(null);
    assertSame(JSch.DEVNULL, JSch.logger, "static logger should be DEVNULL");
    assertSame(JSch.DEVNULL, jsch.getInstanceLogger(), "instance logger should be DEVNULL");
  }

  static final class TestLogger implements Logger {
    @Override
    public boolean isEnabled(int level) {
      return true;
    }

    @Override
    public void log(int level, String message) {
      // empty
    }
  }
}
