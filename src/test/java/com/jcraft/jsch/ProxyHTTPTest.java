package com.jcraft.jsch;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.Test;

public class ProxyHTTPTest {

  @Test
  public void testReadStatus() throws IOException {
    String expected = "HTTP/1.0 Connection Established\r\n";
    InputStream is = new ByteArrayInputStream(expected.getBytes(UTF_8));
    String actual = ProxyHTTP.readStatus(is);
    assertEquals(expected.length() - 2, actual.length());
    assertTrue(expected.startsWith(actual));
  }

  @Test
  public void testReadStatusLong() throws IOException {
    String expected = "HTTP/1.0 ";
    for (int i = 0; i < ProxyHTTP.MAX_STATUS_LEN; i++) {
      expected += "a";
    }
    expected += "\r\n";
    InputStream is = new ByteArrayInputStream(expected.getBytes(UTF_8));
    String actual = ProxyHTTP.readStatus(is);
    assertEquals(ProxyHTTP.MAX_STATUS_LEN, actual.length());
    assertTrue(expected.length() > actual.length());
    assertTrue(expected.startsWith(actual));
  }

  @Test
  public void testReadStatusEmpty() {
    InputStream is = new ByteArrayInputStream(new byte[0]);
    assertThrows(IOException.class, () -> ProxyHTTP.readStatus(is));
  }
}
