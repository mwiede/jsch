package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.test.appender.ListAppender;
import org.apache.logging.log4j.core.test.junit.LoggerContextSource;
import org.apache.logging.log4j.core.test.junit.Named;
import org.apache.logging.log4j.message.Message;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@LoggerContextSource("Log4j2LoggerTest.xml")
public class Log4j2LoggerTest {

  private final Exception testException = new Exception("dummy exception");
  private final ListAppender appender;

  public Log4j2LoggerTest(@Named("List") ListAppender appender) {
    this.appender = appender;
  }

  @BeforeEach
  public void beforeEach() {
    appender.clear();
  }

  @Test
  public void testGetLevel() {
    assertEquals(Level.TRACE, Log4j2Logger.getLevel(-1));

    assertEquals(Level.DEBUG, Log4j2Logger.getLevel(com.jcraft.jsch.Logger.DEBUG));
    assertEquals(Level.ERROR, Log4j2Logger.getLevel(com.jcraft.jsch.Logger.ERROR));
    assertEquals(Level.FATAL, Log4j2Logger.getLevel(com.jcraft.jsch.Logger.FATAL));
    assertEquals(Level.INFO, Log4j2Logger.getLevel(com.jcraft.jsch.Logger.INFO));
    assertEquals(Level.WARN, Log4j2Logger.getLevel(com.jcraft.jsch.Logger.WARN));

    assertEquals(Level.TRACE, Log4j2Logger.getLevel(Integer.MAX_VALUE));
  }

  @Test
  public void testIsEnabled() {
    Log4j2Logger ll = new Log4j2Logger();

    setLevel(Level.ALL);
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertTrue(ll.isEnabled(-1), "trace should be enabled");

    setLevel(Level.DEBUG);
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertFalse(ll.isEnabled(-1), "trace should not be enabled");

    setLevel(Level.ERROR);
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.INFO), "info should not be enabled");
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should not be enabled");
    assertFalse(ll.isEnabled(-1), "trace should not be enabled");

    setLevel(Level.FATAL);
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should not be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.INFO), "info should not be enabled");
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should not be enabled");
    assertFalse(ll.isEnabled(-1), "trace should not be enabled");

    setLevel(Level.INFO);
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertFalse(ll.isEnabled(-1), "trace should not be enabled");

    setLevel(Level.OFF);
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should not be enabled");
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should not be enabled");
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.INFO), "info should not be enabled");
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should not be enabled");
    assertFalse(ll.isEnabled(-1), "trace should not be enabled");

    setLevel(Level.TRACE);
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertTrue(ll.isEnabled(-1), "trace should be enabled");

    setLevel(Level.WARN);
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertFalse(ll.isEnabled(com.jcraft.jsch.Logger.INFO), "info should not be enabled");
    assertTrue(ll.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertFalse(ll.isEnabled(-1), "trace should not be enabled");
  }

  @Test
  public void testLogging() {
    Log4j2Logger ll = new Log4j2Logger();

    List<String> expectedMessages =
        Arrays.asList("debug message", "debug message with null cause", "debug message with cause");
    List<Optional<Throwable>> expectedExceptions =
        Arrays.asList(Optional.empty(), Optional.ofNullable(null), Optional.of(testException));

    setLevel(Level.TRACE);
    ll.log(-1, "debug message");
    ll.log(-1, "debug message with null cause", null);
    ll.log(-1, "debug message with cause", testException);
    checkMessages(expectedMessages, expectedExceptions);

    setLevel(Level.TRACE);
    ll.log(com.jcraft.jsch.Logger.FATAL, "debug message");
    ll.log(com.jcraft.jsch.Logger.FATAL, "debug message with null cause", null);
    ll.log(com.jcraft.jsch.Logger.FATAL, "debug message with cause", testException);
    checkMessages(expectedMessages, expectedExceptions);

    setLevel(Level.ERROR);
    ll.log(-1, "debug message");
    ll.log(-1, "debug message with null cause", null);
    ll.log(-1, "debug message with cause", testException);
    checkMessages(Collections.emptyList(), Collections.emptyList());

    setLevel(Level.ERROR);
    ll.log(com.jcraft.jsch.Logger.FATAL, "debug message");
    ll.log(com.jcraft.jsch.Logger.FATAL, "debug message with null cause", null);
    ll.log(com.jcraft.jsch.Logger.FATAL, "debug message with cause", testException);
    checkMessages(expectedMessages, expectedExceptions);
  }

  private void checkMessages(List<String> expectedMessages,
      List<Optional<Throwable>> expectedExceptions) {
    List<LogEvent> events = appender.getEvents();
    appender.clear();
    List<String> actualMessages = events.stream().map(LogEvent::getMessage)
        .map(Message::getFormattedMessage).collect(Collectors.toList());
    List<Optional<Throwable>> actualExceptions = events.stream().map(LogEvent::getThrown)
        .map(Optional::ofNullable).collect(Collectors.toList());
    assertEquals(expectedMessages, actualMessages, "mismatch in logged messages");
    assertEquals(expectedExceptions, actualExceptions, "mismatch in logged exceptions");
  }

  private static void setLevel(Level level) {
    Configurator.setLevel(JSch.class, level);
  }
}
