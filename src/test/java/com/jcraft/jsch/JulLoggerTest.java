package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JulLoggerTest {
  private LinkedList<String> messages;
  private Exception testException = new Exception("dummy exception");
  @BeforeEach
  void resetLogger() {
    messages = new LinkedList<>();
    Logger logger = Logger.getLogger(getClass().getName());
    Arrays.stream(logger.getHandlers())
      .forEach(logger::removeHandler);
    
  }
  @Test
  void testGetLevel() {
    assertEquals(Level.FINER, JulLogger.getLevel(-1));
    
    assertEquals(Level.FINE, JulLogger.getLevel(com.jcraft.jsch.Logger.DEBUG));
    assertEquals(Level.SEVERE, JulLogger.getLevel(com.jcraft.jsch.Logger.ERROR));
    assertEquals(Level.SEVERE, JulLogger.getLevel(com.jcraft.jsch.Logger.FATAL));
    assertEquals(Level.INFO, JulLogger.getLevel(com.jcraft.jsch.Logger.INFO));
    assertEquals(Level.WARNING, JulLogger.getLevel(com.jcraft.jsch.Logger.WARN));

    assertEquals(Level.FINER, JulLogger.getLevel(Integer.MAX_VALUE));
  }
  
  @Test
  void testIsEnabled() {
    Logger logger = LogManager.getLogManager().getLogger(getClass().getName());
    
    JulLogger jl = new JulLogger(logger);
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
  void testLogging() {
    Logger logger = Logger.getLogger(getClass().getName());
    TestHandler handler = new TestHandler(messages);
    
    logger.addHandler(handler);
    logger.setLevel(Level.ALL);
    JulLogger jl = new JulLogger(logger);
    
    jl.log(-1, "debug message");
    jl.log(-1, "debug message with null cause", null);
    jl.log(-1, "debug message with cause", testException);
    assertEquals("FINER: debug message (without cause)\r\n" + 
        "FINER: debug message with null cause (without cause)\r\n" + 
        "FINER: debug message with cause (with cause java.lang.Exception, dummy exception)", LoggerTest.getMessageLines(messages), "mismatch in logged messages");
    jl.log(com.jcraft.jsch.Logger.FATAL, "debug message");
    jl.log(com.jcraft.jsch.Logger.FATAL, "debug message with null cause", null);
    jl.log(com.jcraft.jsch.Logger.FATAL, "debug message with cause", testException);
    assertEquals("SEVERE: debug message (without cause)\r\n" + 
        "SEVERE: debug message with null cause (without cause)\r\n" + 
        "SEVERE: debug message with cause (with cause java.lang.Exception, dummy exception)", LoggerTest.getMessageLines(messages), "mismatch in logged messages");
    
    logger.setLevel(Level.SEVERE);
    jl.log(-1, "debug message");
    jl.log(-1, "debug message with null cause", null);
    jl.log(-1, "debug message with cause", testException);
    assertEquals("", LoggerTest.getMessageLines(messages), "mismatch in logged messages");
    jl.log(com.jcraft.jsch.Logger.FATAL, "debug message");
    jl.log(com.jcraft.jsch.Logger.FATAL, "debug message with null cause", null);
    jl.log(com.jcraft.jsch.Logger.FATAL, "debug message with cause", testException);
    assertEquals("SEVERE: debug message (without cause)\r\n" + 
        "SEVERE: debug message with null cause (without cause)\r\n" + 
        "SEVERE: debug message with cause (with cause java.lang.Exception, dummy exception)", LoggerTest.getMessageLines(messages), "mismatch in logged messages");
  }
  
  private static class TestHandler extends Handler {
    private LinkedList<String> messages;

    TestHandler(LinkedList<String> messages) {
      this.messages = messages;
    }
    @Override
    public void publish(LogRecord record) {
      Throwable cause = record.getThrown();
      messages.add(record.getLevel() + ": " + record.getMessage() + (cause == null ? " (without cause)" : " (with cause " + cause.getClass().getName() + ", " + cause.getMessage() + ")"));
    }

    @Override
    public void flush() {
      
    }

    @Override
    public void close() throws SecurityException {
      
    }
    
  }
}
