package com.jcraft.jsch;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;

public class Log4j2Logger implements com.jcraft.jsch.Logger {

  private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(JSch.class);

  public Log4j2Logger() {}

  @Override
  public boolean isEnabled(int level) {
    return logger.isEnabled(getLevel(level));
  }

  @Override
  public void log(int level, String message) {
    logger.log(getLevel(level), message);
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
        return Level.ERROR;
      case com.jcraft.jsch.Logger.FATAL:
        return Level.FATAL;
      default:
        return Level.TRACE;
    }
  }
}
