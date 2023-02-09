package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

public class LoggerTest {

  private final Exception testException = new Exception("dummy exception");

  @Test
  public void testLogging() {
    List<String> actualMessages = new ArrayList<>();
    boolean[] enabledResult = new boolean[1];
    Logger logger = new Logger() {
      @Override
      public void log(int level, String message) {
        if (isEnabled(level)) {
          actualMessages.add(level + ":" + message);
        }
      }

      @Override
      public boolean isEnabled(int level) {
        return enabledResult[0];
      }
    };

    actualMessages.clear();
    enabledResult[0] = false;
    logger.log(Logger.ERROR, "debug message");
    logger.log(Logger.ERROR, "debug message with null cause", null);
    logger.log(Logger.ERROR, "debug message with cause", testException);
    assertEquals(Collections.emptyList(), actualMessages, "mismatch in logged messages");

    StringWriter sw = new StringWriter();
    try (PrintWriter pw = new PrintWriter(sw, true)) {
      testException.printStackTrace(pw);
    }
    List<String> expectedMessages = Arrays.asList(Logger.ERROR + ":debug message",
        Logger.ERROR + ":debug message with null cause",
        Logger.ERROR + ":debug message with cause" + System.lineSeparator() + sw);

    actualMessages.clear();
    enabledResult[0] = true;
    logger.log(Logger.ERROR, "debug message");
    logger.log(Logger.ERROR, "debug message with null cause", null);
    logger.log(Logger.ERROR, "debug message with cause", testException);
    assertEquals(expectedMessages, actualMessages, "mismatch in logged messages");
  }
}
