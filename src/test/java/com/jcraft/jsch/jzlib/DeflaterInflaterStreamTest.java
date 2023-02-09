package com.jcraft.jsch.jzlib;

import static com.jcraft.jsch.jzlib.Package.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DeflaterInflaterStreamTest {

  @BeforeEach
  public void before() {}

  @AfterEach
  public void after() {}

  @Test
  public void testDeflaterAndInflaterCanDeflateAndInflateDataOneByOne() throws IOException {
    byte[] data1 = randombuf(1024);
    byte[] buf = new byte[1];

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DeflaterOutputStream gos = new DeflaterOutputStream(baos);
    readArray(data1, gos, buf);
    gos.close();

    ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
    readIS(new InflaterInputStream(new ByteArrayInputStream(baos.toByteArray())), baos2, buf);
    byte[] data2 = baos2.toByteArray();

    assertEquals(data1.length, data2.length);
    assertArrayEquals(data1, data2);
  }

  @Test
  public void testDeflaterOutputStreamAndInflaterInputStreamCanDeflateAndInflate()
      throws IOException {

    for (int i = 1; i < 100; i += 3) {

      byte[] buf = new byte[i];

      byte[] data1 = randombuf(10240);

      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DeflaterOutputStream gos = new DeflaterOutputStream(baos);
      readArray(data1, gos, buf);
      gos.close();

      ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
      readIS(new InflaterInputStream(new ByteArrayInputStream(baos.toByteArray())), baos2, buf);
      byte[] data2 = baos2.toByteArray();

      assertEquals(data1.length, data2.length);
      assertArrayEquals(data1, data2);
    }
  }

  @Test
  public void testDeflaterAndInflaterCanDeflateAndInflateNowrapData() throws IOException {

    for (int i = 1; i < 100; i += 3) {

      byte[] buf = new byte[i];

      byte[] data1 = randombuf(10240);

      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      Deflater deflater = new Deflater(JZlib.Z_DEFAULT_COMPRESSION, JZlib.DEF_WBITS, true);
      DeflaterOutputStream gos = new DeflaterOutputStream(baos, deflater);
      readArray(data1, gos, buf);
      gos.close();

      ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
      Inflater inflater = new Inflater(JZlib.DEF_WBITS, true);
      readIS(new InflaterInputStream(new ByteArrayInputStream(baos.toByteArray()), inflater), baos2,
          buf);
      byte[] data2 = baos2.toByteArray();

      assertEquals(data1.length, data2.length);
      assertArrayEquals(data1, data2);
    }
  }

  @Test
  public void testDeflaterAndInflaterCanDeflateAndInflateNowrapDataWithMaxWbits() {
    byte[] buf = new byte[100];

    Arrays.asList(randombuf(10240),
        "{\"color\":2,\"id\":\"EvLd4UG.CXjnk35o1e8LrYYQfHu0h.d*SqVJPoqmzXM::Ly::Snaps::Store::Commit\"}"
            .getBytes())
        .forEach(uncheckedConsumer(data1 -> {
          Deflater deflater = new Deflater(JZlib.Z_DEFAULT_COMPRESSION, JZlib.MAX_WBITS, true);

          Inflater inflater = new Inflater(JZlib.MAX_WBITS, true);

          ByteArrayOutputStream baos = new ByteArrayOutputStream();
          DeflaterOutputStream gos = new DeflaterOutputStream(baos, deflater);
          readArray(data1, gos, buf);
          gos.close();

          ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
          readIS(new InflaterInputStream(new ByteArrayInputStream(baos.toByteArray()), inflater),
              baos2, buf);
          byte[] data2 = baos2.toByteArray();

          assertEquals(data1.length, data2.length);
          assertArrayEquals(data1, data2);
        }));
  }
}
