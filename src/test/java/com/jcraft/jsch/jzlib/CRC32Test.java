package com.jcraft.jsch.jzlib;

import static com.jcraft.jsch.jzlib.Package.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CRC32Test {
  private CRC32 crc;

  @BeforeEach
  public void before() {
    crc = new CRC32();
  }

  @AfterEach
  public void after() {}

  @Test
  public void testCRC32IsCompatibleWithJavaUtilZipCRC32() {
    byte[] buf1 = randombuf(1024);
    java.util.zip.CRC32 juza = new java.util.zip.CRC32();
    juza.update(buf1, 0, buf1.length);
    long expected = juza.getValue();
    long actual = getValue(Arrays.asList(buf1));

    assertEquals(expected, actual);
  }

  @Test
  public void testCRC2CanCopyItself() {
    byte[] buf1 = randombuf(1024);
    byte[] buf2 = randombuf(1024);

    CRC32 crc1 = new CRC32();

    crc1.update(buf1, 0, buf1.length);

    CRC32 crc2 = crc1.copy();

    crc1.update(buf2, 0, buf1.length);
    crc2.update(buf2, 0, buf1.length);

    long expected = crc1.getValue();
    long actual = crc2.getValue();

    assertEquals(expected, actual);
  }

  @Test
  public void testCRC32CanCombineValues() {

    byte[] buf1 = randombuf(1024);
    byte[] buf2 = randombuf(1024);

    long crc1 = getValue(Arrays.asList(buf1));
    long crc2 = getValue(Arrays.asList(buf2));
    long expected = getValue(Arrays.asList(buf1, buf2));

    long actual = CRC32.combine(crc1, crc2, buf2.length);

    assertEquals(expected, actual);
  }

  private synchronized long getValue(List<byte[]> buf) {
    crc.reset();
    buf.forEach(b -> crc.update(b, 0, b.length));
    return crc.getValue();
  }
}
