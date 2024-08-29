package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.valfirst.slf4jtest.LoggingEvent;
import com.github.valfirst.slf4jtest.TestLogger;
import com.github.valfirst.slf4jtest.TestLoggerFactory;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

public class Slf4jLoggerTest {

  private static final TestLogger logger = TestLoggerFactory.getTestLogger(JSch.class);

  private final Set<Level> OFF_LEVELS = EnumSet.noneOf(Level.class);
  private final Set<Level> TRACE_LEVELS =
      EnumSet.of(Level.TRACE, Level.DEBUG, Level.INFO, Level.WARN, Level.ERROR);
  private final Set<Level> DEBUG_LEVELS =
      EnumSet.of(Level.DEBUG, Level.INFO, Level.WARN, Level.ERROR);
  private final Set<Level> INFO_LEVELS = EnumSet.of(Level.INFO, Level.WARN, Level.ERROR);
  private final Set<Level> WARN_LEVELS = EnumSet.of(Level.WARN, Level.ERROR);
  private final Set<Level> ERROR_LEVELS = EnumSet.of(Level.ERROR);

  private final Exception testException = new Exception("dummy exception");

  @BeforeEach
  public void beforeEach() {
    logger.clearAll();
  }

  @AfterAll
  public static void afterAll() {
    logger.clearAll();
  }

  @Test
  public void testIsEnabled() {
    Slf4jLogger sl = new Slf4jLogger();

    logger.setEnabledLevelsForAllThreads(DEBUG_LEVELS);
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertFalse(sl.isEnabled(-1), "trace should not be enabled");

    logger.setEnabledLevelsForAllThreads(ERROR_LEVELS);
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should not be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should not be enabled");
    assertFalse(sl.isEnabled(-1), "trace should not be enabled");

    logger.setEnabledLevelsForAllThreads(INFO_LEVELS);
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertFalse(sl.isEnabled(-1), "trace should not be enabled");

    logger.setEnabledLevelsForAllThreads(OFF_LEVELS);
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should not be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should not be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should not be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should not be enabled");
    assertFalse(sl.isEnabled(-1), "trace should not be enabled");

    logger.setEnabledLevelsForAllThreads(TRACE_LEVELS);
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertTrue(sl.isEnabled(-1), "trace should be enabled");

    logger.setEnabledLevelsForAllThreads(WARN_LEVELS);
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.DEBUG), "debug should not be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.ERROR), "error should be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.FATAL), "fatal should be enabled");
    assertFalse(sl.isEnabled(com.jcraft.jsch.Logger.INFO), "info should not be enabled");
    assertTrue(sl.isEnabled(com.jcraft.jsch.Logger.WARN), "warn should be enabled");
    assertFalse(sl.isEnabled(-1), "trace should not be enabled");
  }

  @Test
  public void testLogging() {
    Slf4jLogger sl = new Slf4jLogger();

    List<String> expectedMessages =
        Arrays.asList("debug message", "debug message with null cause", "debug message with cause");
    List<Optional<Throwable>> expectedExceptions =
        Arrays.asList(Optional.empty(), Optional.ofNullable(null), Optional.of(testException));

    logger.setEnabledLevelsForAllThreads(TRACE_LEVELS);
    sl.log(-1, "debug message");
    sl.log(-1, "debug message with null cause", null);
    sl.log(-1, "debug message with cause", testException);
    checkMessages(expectedMessages, expectedExceptions);

    logger.setEnabledLevelsForAllThreads(TRACE_LEVELS);
    sl.log(com.jcraft.jsch.Logger.FATAL, "debug message");
    sl.log(com.jcraft.jsch.Logger.FATAL, "debug message with null cause", null);
    sl.log(com.jcraft.jsch.Logger.FATAL, "debug message with cause", testException);
    checkMessages(expectedMessages, expectedExceptions);

    logger.setEnabledLevelsForAllThreads(ERROR_LEVELS);
    sl.log(-1, "debug message");
    sl.log(-1, "debug message with null cause", null);
    sl.log(-1, "debug message with cause", testException);
    checkMessages(Collections.emptyList(), Collections.emptyList());

    logger.setEnabledLevelsForAllThreads(ERROR_LEVELS);
    sl.log(com.jcraft.jsch.Logger.FATAL, "debug message");
    sl.log(com.jcraft.jsch.Logger.FATAL, "debug message with null cause", null);
    sl.log(com.jcraft.jsch.Logger.FATAL, "debug message with cause", testException);
    checkMessages(expectedMessages, expectedExceptions);
  }

  private void checkMessages(List<String> expectedMessages,
      List<Optional<Throwable>> expectedExceptions) {
    List<LoggingEvent> events = logger.getAllLoggingEvents();
    logger.clearAll();
    List<String> actualMessages =
        events.stream().map(LoggingEvent::getFormattedMessage).collect(Collectors.toList());
    List<Optional<Throwable>> actualExceptions =
        events.stream().map(LoggingEvent::getThrowable).collect(Collectors.toList());
    assertEquals(expectedMessages, actualMessages, "mismatch in logged messages");
    assertEquals(expectedExceptions, actualExceptions, "mismatch in logged exceptions");
  }
}
