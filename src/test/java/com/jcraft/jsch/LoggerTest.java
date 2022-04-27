package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedList;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class LoggerTest {
  
  @Test
  void testLogWithCause() {
    LinkedList<String> messages = new LinkedList<>();
    boolean[] enabledResult = new boolean[1];
    Logger logger = new Logger() {
      @Override
      public void log(int level, String message) {
        messages.add(level + ":" + message);
      }
      @Override
      public boolean isEnabled(int level) {
        return enabledResult[0];
      }
    };
    
    Exception ex = new Exception("dummy exception");
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    ex.printStackTrace(pw);
    String expectedTrace = sw.toString();
    
    logger.log(Logger.ERROR, "some message", null);
    logger.log(Logger.ERROR, "some message with trace", ex);
    assertEquals("", getMessageLines(messages), "message mismatch");
    
    enabledResult[0] = true;
    logger.log(Logger.ERROR, "some message", null);
    logger.log(Logger.ERROR, "some message with trace", ex);
    assertEquals(
        Logger.ERROR + ":some message\r\n" + 
        Logger.ERROR + ":some message with trace\r\n" + 
        expectedTrace +
        "", getMessageLines(messages), "message mismatch");
  }
  
  static String getMessageLines(LinkedList<String> messages) {
    try {
      return messages.stream()
          .map(line -> line.replaceAll("\\r?\\n", "\r\n"))
          .collect(Collectors.joining("\r\n"));
    }
    finally {
      messages.clear();
    }
  }
}
