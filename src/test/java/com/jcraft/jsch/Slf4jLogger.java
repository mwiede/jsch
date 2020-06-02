package com.jcraft.jsch;

import org.slf4j.LoggerFactory;

public class Slf4jLogger implements com.jcraft.jsch.Logger {

  private static final org.slf4j.Logger log = LoggerFactory.getLogger(JSch.class);
  private static final com.jcraft.jsch.Logger instance = new Slf4jLogger();

  private Slf4jLogger() {}

  @Override
  public boolean isEnabled(int level) {
    switch (level) {
      case com.jcraft.jsch.Logger.DEBUG:
        return log.isDebugEnabled();
      case com.jcraft.jsch.Logger.INFO:
        return log.isInfoEnabled();
      case com.jcraft.jsch.Logger.WARN:
        return log.isWarnEnabled();
      case com.jcraft.jsch.Logger.ERROR:
      case com.jcraft.jsch.Logger.FATAL:
        return log.isErrorEnabled();
      default:
        return log.isTraceEnabled();
    }
  }

  @Override
  public void log(int level, String message) {
    switch (level) {
      case com.jcraft.jsch.Logger.DEBUG:
        log.debug(message);
        break;
      case com.jcraft.jsch.Logger.INFO:
        log.info(message);
        break;
      case com.jcraft.jsch.Logger.WARN:
        log.warn(message);
        break;
      case com.jcraft.jsch.Logger.ERROR:
      case com.jcraft.jsch.Logger.FATAL:
        log.error(message);
        break;
      default:
        log.trace(message);
        break;
    }
  }

  public static com.jcraft.jsch.Logger getInstance() {
    return instance;
  }
}
