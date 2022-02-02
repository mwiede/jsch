package com.jcraft.jsch;

import org.slf4j.LoggerFactory;

public class Slf4jLogger implements com.jcraft.jsch.Logger {

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(JSch.class);

  public Slf4jLogger() {}

  @Override
  public boolean isEnabled(int level) {
    switch (level) {
      case com.jcraft.jsch.Logger.DEBUG:
        return logger.isDebugEnabled();
      case com.jcraft.jsch.Logger.INFO:
        return logger.isInfoEnabled();
      case com.jcraft.jsch.Logger.WARN:
        return logger.isWarnEnabled();
      case com.jcraft.jsch.Logger.ERROR:
      case com.jcraft.jsch.Logger.FATAL:
        return logger.isErrorEnabled();
      default:
        return logger.isTraceEnabled();
    }
  }

  @Override
  public void log(int level, String message) {
    switch (level) {
      case com.jcraft.jsch.Logger.DEBUG:
        logger.debug(message);
        break;
      case com.jcraft.jsch.Logger.INFO:
        logger.info(message);
        break;
      case com.jcraft.jsch.Logger.WARN:
        logger.warn(message);
        break;
      case com.jcraft.jsch.Logger.ERROR:
      case com.jcraft.jsch.Logger.FATAL:
        logger.error(message);
        break;
      default:
        logger.trace(message);
        break;
    }
  }
}
