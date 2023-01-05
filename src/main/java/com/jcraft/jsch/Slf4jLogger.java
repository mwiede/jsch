package com.jcraft.jsch;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JSch logger to log entries using the SLF4J framework
 */
public class Slf4jLogger implements com.jcraft.jsch.Logger {

  private static final Logger logger = LoggerFactory.getLogger(JSch.class);

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
    log(level, message, null);
  }

  @Override
  public void log(int level, String message, Throwable cause) {
    if (!isEnabled(level)) {
      return;
    }
    switch (level) {
      case com.jcraft.jsch.Logger.DEBUG:
        logger.debug(message, cause);
        break;
      case com.jcraft.jsch.Logger.INFO:
        logger.info(message, cause);
        break;
      case com.jcraft.jsch.Logger.WARN:
        logger.warn(message, cause);
        break;
      case com.jcraft.jsch.Logger.ERROR:
      case com.jcraft.jsch.Logger.FATAL:
        logger.error(message, cause);
        break;
      default:
        logger.trace(message, cause);
        break;
    }
  }
}
