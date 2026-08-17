package com.jcraft.jsch;

import static com.jcraft.jsch.SftpATTRS.MAX_EXTENDED_COUNT;
import static com.jcraft.jsch.SftpATTRS.SSH_FILEXFER_ATTR_EXTENDED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.ZoneOffset;
import java.util.Date;
import java.util.Random;
import java.util.TimeZone;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class SftpATTRSTest {

  private static TimeZone timezone;
  private final Random random = new Random();

  @BeforeAll
  public static void beforeAll() {
    timezone = TimeZone.getDefault();
    TimeZone.setDefault(TimeZone.getTimeZone(ZoneOffset.UTC));
  }

  @AfterAll
  public static void afterAll() {
    TimeZone.setDefault(timezone);
  }

  @Test
  public void testToDateString0() {
    String expected = new Date(0L).toString();
    String actual = SftpATTRS.toDateString(0L);
    assertEquals(expected, actual);
  }

  @Test
  public void testToDateStringNow() {
    long now = System.currentTimeMillis() / 1000L;
    String expected = new Date(now * 1000L).toString();
    String actual = SftpATTRS.toDateString(now);
    assertEquals(expected, actual);
  }

  @Test
  public void testToDateStringRandom() {
    for (int i = 0; i < 1000000; i++) {
      int j = random.ints(Integer.MIN_VALUE, Integer.MAX_VALUE).findFirst().getAsInt();
      long l = Integer.toUnsignedLong(j);
      String expected = new Date(l * 1000L).toString();
      String actual = SftpATTRS.toDateString(l);
      assertEquals(expected, actual);
    }
  }

  @Test
  public void testGetATTRNegativeExtendedCount() {
    Buffer buf = new Buffer(8);
    buf.putInt(SSH_FILEXFER_ATTR_EXTENDED);
    buf.putInt(-1);
    assertThrows(SftpException.class, () -> SftpATTRS.getATTR(buf));
  }

  @Test
  public void testGetATTRMaxExtendedCount() {
    Buffer buf = new Buffer(8);
    buf.putInt(SSH_FILEXFER_ATTR_EXTENDED);
    buf.putInt(MAX_EXTENDED_COUNT + 1);
    assertThrows(SftpException.class, () -> SftpATTRS.getATTR(buf));
  }

  @Test
  public void testGetATTRInvalidExtendedCount() {
    Buffer buf = new Buffer(8);
    buf.putInt(SSH_FILEXFER_ATTR_EXTENDED);
    buf.putInt(1);
    assertThrows(SftpException.class, () -> SftpATTRS.getATTR(buf));
  }

  @Test
  public void testGetATTREmptyExtendedCount() throws Exception {
    Buffer buf = new Buffer(8);
    buf.putInt(SSH_FILEXFER_ATTR_EXTENDED);
    buf.putInt(0);
    SftpATTRS attrs = SftpATTRS.getATTR(buf);
    String[] extended = attrs.getExtended();
    assertNull(extended);
  }

  @Test
  public void testGetATTRValidExtendedCount() throws Exception {
    Buffer buf = new Buffer(16);
    buf.putInt(SSH_FILEXFER_ATTR_EXTENDED);
    buf.putInt(1);
    buf.putString(Util.str2byte(""));
    buf.putString(Util.str2byte(""));
    SftpATTRS attrs = SftpATTRS.getATTR(buf);
    String[] extended = attrs.getExtended();
    assertNotNull(extended);
    assertEquals(2, extended.length);
    assertEquals("", extended[0]);
    assertEquals("", extended[1]);
  }
}
