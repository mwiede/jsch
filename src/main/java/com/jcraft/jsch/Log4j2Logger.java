package com.jcraft.jsch;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Log4j2Logger implements com.jcraft.jsch.Logger {

  private static final Logger logger = LogManager.getLogger(JSch.class);

  public Log4j2Logger() {}

  @Override
  public boolean isEnabled(int level) {
    return logger.isEnabled(getLevel(level));
  }

  @Override
  public void log(int level, String message) {
    logger.log(getLevel(level), message);
  }

  @Override
  public void log(int level, String message, Throwable cause) {
    if (cause == null) {
      logger.log(getLevel(level), message);
      return;
    }
    logger.log(getLevel(level), message, cause);
  }

  static Level getLevel(int level) {
    switch (level) {
      case com.jcraft.jsch.Logger.DEBUG:
        return Level.DEBUG;
      case com.jcraft.jsch.Logger.INFO:
        return Level.INFO;
      case com.jcraft.jsch.Logger.WARN:
        return Level.WARN;
      case com.jcraft.jsch.Logger.ERROR:
        return Level.ERROR;
      case com.jcraft.jsch.Logger.FATAL:
        return Level.FATAL;
      default:
        return Level.TRACE;
    }
  }
}
