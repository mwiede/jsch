package com.jcraft.jsch;

import java.lang.System.Logger.Level;

public class JplLogger implements com.jcraft.jsch.Logger {

  private static final System.Logger logger = System.getLogger(JSch.class.getName());

  public JplLogger() {}

  @Override
  public boolean isEnabled(int level) {
    return logger.isLoggable(getLevel(level));
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
        return Level.WARNING;
      case com.jcraft.jsch.Logger.ERROR:
      case com.jcraft.jsch.Logger.FATAL:
        return Level.ERROR;
      default:
        return Level.TRACE;
    }
  }
}
