package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class JulLoggerTest {

  private static final Logger logger = Logger.getLogger(JSch.class.getName());
  private static final ListHandler handler = new ListHandler();

  private final Exception testException = new Exception("dummy exception");

  @BeforeAll
  public static void beforeAll() {
    LogManager.getLogManager().reset();
    Arrays.stream(logger.getHandlers()).forEach(logger::removeHandler);
    logger.addHandler(handler);
    logger.setLevel(Level.ALL);
    logger.setUseParentHandlers(false);
    Logger.getLogger("").setLevel(Level.OFF);
  }

  @BeforeEach
  public void beforeEach() {
    handler.clear();
  }

  @AfterAll
  public static void afterAll() {
    LogManager.getLogManager().reset();
  }

  @Test
  public void testGetLevel() {
    assertEquals(Level.FINER, JulLogger.getLevel(-1));

    assertEquals(Level.FINE, JulLogger.getLevel(com.jcraft.jsch.Logger.DEBUG));
    assertEquals(Level.SEVERE, JulLogger.getLevel(com.jcraft.jsch.Logger.ERROR));
    assertEquals(Level.SEVERE, JulLogger.getLevel(com.jcraft.jsch.Logger.FATAL));
    assertEquals(Level.INFO, JulLogger.getLevel(com.jcraft.jsch.Logger.INFO));
    assertEquals(Level.WARNING, JulLogger.getLevel(com.jcraft.jsch.Logger.WARN));

    assertEquals(Level.FINER, JulLogger.getLevel(Integer.MAX_VALUE));
  }

  @Test
  public void testIsEnabled() {
    JulLogger jl = new JulLogger();

    logger.setLevel(Level.FINEST);
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertTrue(jl.isEnabled(-1), "trace should be enabled");

    logger.setLevel(Level.FINE);
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertFalse(jl.isEnabled(-1), "trace should not be enabled");

    logger.setLevel(Level.SEVERE);
    assertFalse(jl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertFalse(jl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should not be enabled");
    assertFalse(jl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should not be enabled");
    assertFalse(jl.isEnabled(-1), "trace should not be enabled");

    logger.setLevel(Level.INFO);
    assertFalse(jl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertFalse(jl.isEnabled(-1), "trace should not be enabled");

    logger.setLevel(Level.OFF);
    assertFalse(jl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertFalse(jl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should not be enabled");
    assertFalse(jl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should not be enabled");
    assertFalse(jl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should not be enabled");
    assertFalse(jl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should not be enabled");
    assertFalse(jl.isEnabled(-1), "trace should not be enabled");

    logger.setLevel(Level.FINER);
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertTrue(jl.isEnabled(-1), "trace should be enabled");

    logger.setLevel(Level.WARNING);
    assertFalse(jl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertFalse(jl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should not be enabled");
    assertTrue(jl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertFalse(jl.isEnabled(-1), "trace should not be enabled");
  }

  @Test
  public void testLogging() {
    JulLogger jl = new JulLogger();

    List<String> expectedMessages =
        Arrays.asList("debug message", "debug message with null cause", "debug message with cause");
    List<Optional<Throwable>> expectedExceptions =
        Arrays.asList(Optional.empty(), Optional.ofNullable(null), Optional.of(testException));

    logger.setLevel(Level.ALL);
    jl.log(-1, "debug message");
    jl.log(-1, "debug message with null cause", null);
    jl.log(-1, "debug message with cause", testException);
    checkMessages(expectedMessages, expectedExceptions);

    logger.setLevel(Level.ALL);
    jl.log(com.jcraft.jsch.Logger.FATAL, "debug message");
    jl.log(com.jcraft.jsch.Logger.FATAL, "debug message with null cause", null);
    jl.log(com.jcraft.jsch.Logger.FATAL, "debug message with cause", testException);
    checkMessages(expectedMessages, expectedExceptions);

    logger.setLevel(Level.SEVERE);
    jl.log(-1, "debug message");
    jl.log(-1, "debug message with null cause", null);
    jl.log(-1, "debug message with cause", testException);
    checkMessages(Collections.emptyList(), Collections.emptyList());

    logger.setLevel(Level.SEVERE);
    jl.log(com.jcraft.jsch.Logger.FATAL, "debug message");
    jl.log(com.jcraft.jsch.Logger.FATAL, "debug message with null cause", null);
    jl.log(com.jcraft.jsch.Logger.FATAL, "debug message with cause", testException);
    checkMessages(expectedMessages, expectedExceptions);
  }

  private void checkMessages(List<String> expectedMessages,
      List<Optional<Throwable>> expectedExceptions) {
    List<LogRecord> records = handler.getRecords();
    handler.clear();
    List<String> actualMessages =
        records.stream().map(LogRecord::getMessage).collect(Collectors.toList());
    List<Optional<Throwable>> actualExceptions = records.stream().map(LogRecord::getThrown)
        .map(Optional::ofNullable).collect(Collectors.toList());
    assertEquals(expectedMessages, actualMessages, "mismatch in logged messages");
    assertEquals(expectedExceptions, actualExceptions, "mismatch in logged exceptions");
  }

  public static class ListHandler extends Handler {
    private final List<LogRecord> records;

    public ListHandler() {
      super();
      records = Collections.synchronizedList(new ArrayList<>());
    }

    @Override
    public void publish(LogRecord record) {
      records.add(record);
    }

    @Override
    public void flush() {}

    @Override
    public void close() throws SecurityException {}

    public List<LogRecord> getRecords() {
      return Collections.unmodifiableList(new ArrayList<>(records));
    }

    public void clear() {
      synchronized (records) {
        records.clear();
        setLevel(Level.ALL);
      }
    }
  }
}
