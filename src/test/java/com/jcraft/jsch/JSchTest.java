package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Hashtable;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
  void setPubkeyAcceptedKeyTypesHashtable() throws JSchException {
    Hashtable<String, String> newconf = new Hashtable<>();
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

  @Test
  void getConfigKeys() throws Exception {
    Set<String> keys = JSch.getConfigKeys();
    // there are many keys so just assert a high number in case new keys
    // are added so this test still passes

    int before = keys.size();

    assertTrue(before > 150);
    assertTrue(keys.contains("diffie-hellman-group14-sha256"));
    assertTrue(keys.contains("HashKnownHosts"));

    // add new key
    JSch.setConfig("mySpecialKey", "mySpecialValue");

    // add 1 new key
    keys = JSch.getConfigKeys();
    int after = keys.size();
    assertEquals(before + 1, after);
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
