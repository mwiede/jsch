package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.LinkedList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.pattern.ThrowableProxyConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.AppenderBase;

class Slf4jLoggerTest {
  private LinkedList<String> messages;
  private Exception testException = new Exception("dummy exception");
  private ThrowableProxyConverter tpc = new ThrowableProxyConverter();

  @BeforeEach
  void resetLogger() {
    Logger logger = LoggerFactory.getLogger(getClass());
    assertNotNull(logger, "logger should not be null");
    assertEquals("ch.qos.logback.classic.Logger", logger.getClass().getName(),
        "we need logback as backend for slf4j to test");
    ch.qos.logback.classic.Logger lbLogger = (ch.qos.logback.classic.Logger) logger;
    lbLogger.iteratorForAppenders().forEachRemaining(lbLogger::detachAppender);
    messages = new LinkedList<>();

    tpc.start();
  }

  @Test
  void testIsEnabled() {
    LoggerContext ct = (LoggerContext) LoggerFactory.getILoggerFactory();
    ch.qos.logback.classic.Logger lbLogger = ct.getLogger(getClass());
    lbLogger.addAppender(new TestAppender(messages));
    lbLogger.setLevel(Level.ALL);
    Slf4jLogger sl = new Slf4jLogger(lbLogger);

    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertTrue(sl.isEnabled(-1), "trace should be enabled");

    lbLogger.setLevel(Level.DEBUG);
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertFalse(sl.isEnabled(-1), "trace should not be enabled");

    lbLogger.setLevel(Level.ERROR);
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should not be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should not be enabled");
    assertFalse(sl.isEnabled(-1), "trace should not be enabled");

    lbLogger.setLevel(Level.INFO);
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertFalse(sl.isEnabled(-1), "trace should not be enabled");

    lbLogger.setLevel(Level.OFF);
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should not be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should not be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should not be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should not be enabled");
    assertFalse(sl.isEnabled(-1), "trace should not be enabled");

    lbLogger.setLevel(Level.TRACE);
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertTrue(sl.isEnabled(-1), "trace should be enabled");

    lbLogger.setLevel(Level.WARN);
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should not be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertFalse(sl.isEnabled(-1), "trace should not be enabled");
  }

  @Test
  void testLogging() {
    LoggerContext ct = (LoggerContext) LoggerFactory.getILoggerFactory();
    ch.qos.logback.classic.Logger lbLogger = ct.getLogger(getClass());
    TestAppender app = new TestAppender(messages);
    app.setContext(ct);
    app.start();
    lbLogger.addAppender(app);
    lbLogger.setAdditive(false);
    lbLogger.setLevel(Level.ALL);
    Slf4jLogger sl = new Slf4jLogger(lbLogger);

    sl.log(-1, "debug message");
    sl.log(-1, "debug message with null cause", null);
    sl.log(-1, "debug message with cause", testException);
    assertEquals(
        "TRACE: debug message (without cause)\r\n"
            + "TRACE: debug message with null cause (without cause)\r\n"
            + "TRACE: debug message with cause (with cause java.lang.Exception, dummy exception)",
        LoggerTest.getMessageLines(messages), "mismatch in logged messages");
    sl.log(com.jcraft.jsch.Logger.FATAL, "debug message");
    sl.log(com.jcraft.jsch.Logger.FATAL, "debug message with null cause", null);
    sl.log(com.jcraft.jsch.Logger.FATAL, "debug message with cause", testException);
    assertEquals(
        "ERROR: debug message (without cause)\r\n"
            + "ERROR: debug message with null cause (without cause)\r\n"
            + "ERROR: debug message with cause (with cause java.lang.Exception, dummy exception)",
        LoggerTest.getMessageLines(messages), "mismatch in logged messages");

    lbLogger.setLevel(Level.ERROR);
    sl.log(-1, "debug message");
    sl.log(-1, "debug message with null cause", null);
    sl.log(-1, "debug message with cause", testException);
    assertEquals("", LoggerTest.getMessageLines(messages), "mismatch in logged messages");
    sl.log(com.jcraft.jsch.Logger.FATAL, "debug message");
    sl.log(com.jcraft.jsch.Logger.FATAL, "debug message with null cause", null);
    sl.log(com.jcraft.jsch.Logger.FATAL, "debug message with cause", testException);
    assertEquals(
        "ERROR: debug message (without cause)\r\n"
            + "ERROR: debug message with null cause (without cause)\r\n"
            + "ERROR: debug message with cause (with cause java.lang.Exception, dummy exception)",
        LoggerTest.getMessageLines(messages), "mismatch in logged messages");
  }

  static class TestAppender extends AppenderBase<ILoggingEvent> {
    private LinkedList<String> messages;

    TestAppender(LinkedList<String> messages) {
      this.messages = messages;
    }

    @Override
    protected void append(ILoggingEvent eventObject) {
      try {
        IThrowableProxy thp = eventObject.getThrowableProxy();

        messages.add(eventObject.getLevel() + ": " + eventObject.getMessage()
            + (thp == null ? " (without cause)"
                : " (with cause " + thp.getClassName() + ", " + thp.getMessage() + ")"));
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }
}
