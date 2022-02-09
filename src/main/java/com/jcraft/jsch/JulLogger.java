package com.jcraft.jsch;

import java.util.logging.Level;

public class JulLogger implements com.jcraft.jsch.Logger {

  private static final java.util.logging.Logger logger = java.util.logging.Logger.getLogger(JSch.class.getName());

  public JulLogger() {}

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
        return Level.FINE;
      case com.jcraft.jsch.Logger.INFO:
        return Level.INFO;
      case com.jcraft.jsch.Logger.WARN:
        return Level.WARNING;
      case com.jcraft.jsch.Logger.ERROR:
      case com.jcraft.jsch.Logger.FATAL:
        return Level.SEVERE;
      default:
        return Level.FINER;
    }
  }
}
