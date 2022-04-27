package com.jcraft.jsch;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import org.slf4j.spi.LoggingEventBuilder;

public class Slf4jLogger implements com.jcraft.jsch.Logger {

  private static final Logger stlogger = LoggerFactory.getLogger(JSch.class);
  private Logger logger;

  public Slf4jLogger() {
    this(stlogger);
  }

  Slf4jLogger(Logger logger) {
    this.logger = logger;
  }

  @Override
  public boolean isEnabled(int level) {
    return logger.isEnabledForLevel(getLevel(level));
  }

  @Override
  public void log(int level, String message) {
    log (level, message, null);
  }

  @Override
  public void log(int level, String message, Throwable cause) {
    if (!isEnabled(level)) {
      return;
    }
    LoggingEventBuilder builder = logger.makeLoggingEventBuilder(getLevel(level));
    if (cause != null) {
      builder.setCause(cause);
    }
    builder.log(message);
  }

  private static Level getLevel(int level) {
    switch (level) {
      case com.jcraft.jsch.Logger.DEBUG:
        return Level.DEBUG;
      case com.jcraft.jsch.Logger.INFO:
        return Level.INFO;
      case com.jcraft.jsch.Logger.WARN:
        return Level.WARN;
      case com.jcraft.jsch.Logger.ERROR:
      case com.jcraft.jsch.Logger.FATAL:
        return Level.ERROR;
      default:
        return Level.TRACE;
    }
  }
}
