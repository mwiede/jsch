package com.jcraft.jsch.jzlib;

import static com.jcraft.jsch.jzlib.Package.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class Adler32Test {
  private Adler32 adler;

  @BeforeEach
  public void before() {
    adler = new Adler32();
  }

  @AfterEach
  public void after() {}

  @Test
  public void testAdler32IsCompatibleWithJavaUtilZipAdler32() {
    byte[] buf1 = randombuf(1024);
    java.util.zip.Adler32 juza = new java.util.zip.Adler32();
    juza.update(buf1, 0, buf1.length);
    long expected = juza.getValue();
    long actual = getValue(Arrays.asList(buf1));

    assertEquals(expected, actual);
  }

  @Test
  public void testAdler32CanCopyItself() {
    byte[] buf1 = randombuf(1024);
    byte[] buf2 = randombuf(1024);

    Adler32 adler1 = new Adler32();

    adler1.update(buf1, 0, buf1.length);

    Adler32 adler2 = adler1.copy();

    adler1.update(buf2, 0, buf1.length);
    adler2.update(buf2, 0, buf1.length);

    long expected = adler1.getValue();
    long actual = adler2.getValue();

    assertEquals(expected, actual);
  }

  @Test
  public void testAdler32CanCombineValues() {

    byte[] buf1 = randombuf(1024);
    byte[] buf2 = randombuf(1024);

    long adler1 = getValue(Arrays.asList(buf1));
    long adler2 = getValue(Arrays.asList(buf2));
    long expected = getValue(Arrays.asList(buf1, buf2));

    long actual = Adler32.combine(adler1, adler2, buf2.length);

    assertEquals(expected, actual);
  }

  private synchronized long getValue(List<byte[]> buf) {
    adler.reset();
    buf.forEach(b -> adler.update(b, 0, b.length));
    return adler.getValue();
  }
}
