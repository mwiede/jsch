package com.jcraft.jsch.jzlib;

import static com.jcraft.jsch.jzlib.JZlib.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DeflateInflateTest {
  private final int comprLen = 40000;
  private final int uncomprLen = comprLen;
  private byte[] compr;
  private byte[] uncompr;

  private Deflater deflater;
  private Inflater inflater;
  private int err;

  @BeforeEach
  public void before() {
    compr = new byte[comprLen];
    uncompr = new byte[uncomprLen];

    deflater = new Deflater();
    inflater = new Inflater();

    err = Z_OK;
  }

  @AfterEach
  public void after() {}

  @Test
  public void testDeflaterAndInflaterCanDeflateAndInflateDataInLargeBuffer() {
    err = deflater.init(Z_BEST_SPEED);
    assertEquals(Z_OK, err);

    deflater.setInput(uncompr);
    deflater.setOutput(compr);

    err = deflater.deflate(Z_NO_FLUSH);
    assertEquals(Z_OK, err);

    assertEquals(0, deflater.avail_in);

    deflater.params(Z_NO_COMPRESSION, Z_DEFAULT_STRATEGY);
    deflater.setInput(compr);
    deflater.avail_in = comprLen / 2;

    err = deflater.deflate(Z_NO_FLUSH);
    assertEquals(Z_OK, err);

    deflater.params(Z_BEST_COMPRESSION, Z_FILTERED);
    deflater.setInput(uncompr);
    deflater.avail_in = uncomprLen;

    err = deflater.deflate(Z_NO_FLUSH);
    assertEquals(Z_OK, err);

    err = deflater.deflate(JZlib.Z_FINISH);
    assertEquals(Z_STREAM_END, err);

    err = deflater.end();
    assertEquals(Z_OK, err);

    inflater.setInput(compr);

    err = inflater.init();
    assertEquals(Z_OK, err);

    boolean loop = true;
    while (loop) {
      inflater.setOutput(uncompr);
      err = inflater.inflate(Z_NO_FLUSH);
      if (err == Z_STREAM_END)
        loop = false;
      else
        assertEquals(Z_OK, err);
    }

    err = inflater.end();
    assertEquals(Z_OK, err);

    int total_out = (int) inflater.total_out;

    assertEquals(2 * uncomprLen + comprLen / 2, total_out);
  }

  @Test
  public void testDeflaterAndInflaterCanDeflateAndInflateDataInSmallBuffer() {
    byte[] data = "hello, hello!".getBytes(UTF_8);

    err = deflater.init(Z_DEFAULT_COMPRESSION);
    assertEquals(Z_OK, err);

    deflater.setInput(data);
    deflater.setOutput(compr);

    while (deflater.total_in < data.length && deflater.total_out < comprLen) {
      deflater.avail_in = 1;
      deflater.avail_out = 1;
      err = deflater.deflate(Z_NO_FLUSH);
      assertEquals(Z_OK, err);
    }

    do {
      deflater.avail_out = 1;
      err = deflater.deflate(Z_FINISH);
    } while (err != Z_STREAM_END);

    err = deflater.end();
    assertEquals(Z_OK, err);

    inflater.setInput(compr);
    inflater.setOutput(uncompr);

    err = inflater.init();
    assertEquals(Z_OK, err);

    boolean loop = true;
    while (inflater.total_out < uncomprLen && inflater.total_in < comprLen && loop) {
      inflater.avail_in = 1; // force small buffers
      inflater.avail_out = 1; // force small buffers
      err = inflater.inflate(Z_NO_FLUSH);
      if (err == Z_STREAM_END)
        loop = false;
      else
        assertEquals(Z_OK, err);
    }

    err = inflater.end();
    assertEquals(Z_OK, err);

    int total_out = (int) inflater.total_out;
    byte[] actual = new byte[total_out];
    System.arraycopy(uncompr, 0, actual, 0, total_out);

    assertArrayEquals(data, actual);
  }

  @Test
  public void testDeflaterAndInflaterSupportDictionary() {
    byte[] hello = "hello".getBytes(UTF_8);
    byte[] dictionary = "hello, hello!".getBytes(UTF_8);

    err = deflater.init(Z_DEFAULT_COMPRESSION);
    assertEquals(Z_OK, err);

    deflater.setDictionary(dictionary, dictionary.length);
    assertEquals(Z_OK, err);

    long dictID = deflater.getAdler();

    deflater.setInput(hello);
    deflater.setOutput(compr);

    err = deflater.deflate(Z_FINISH);
    assertEquals(Z_STREAM_END, err);

    err = deflater.end();
    assertEquals(Z_OK, err);

    err = inflater.init();
    assertEquals(Z_OK, err);

    inflater.setInput(compr);
    inflater.setOutput(uncompr);

    boolean loop = true;
    do {
      err = inflater.inflate(JZlib.Z_NO_FLUSH);
      switch (err) {
        case Z_STREAM_END:
          loop = false;
          break;
        case Z_NEED_DICT:
          assertEquals(inflater.getAdler(), dictID);
          err = inflater.setDictionary(dictionary, dictionary.length);
          assertEquals(Z_OK, err);
          break;
        default:
          assertEquals(Z_OK, err);
          break;
      }
    } while (loop);

    err = inflater.end();
    assertEquals(Z_OK, err);

    int total_out = (int) inflater.total_out;
    byte[] actual = new byte[total_out];
    System.arraycopy(uncompr, 0, actual, 0, total_out);

    assertArrayEquals(hello, actual);
  }

  @Test
  public void testDeflaterAndInflaterSupportSync() {
    byte[] hello = "hello".getBytes(UTF_8);

    err = deflater.init(Z_DEFAULT_COMPRESSION);
    assertEquals(Z_OK, err);

    deflater.setInput(hello);
    deflater.avail_in = 3;
    deflater.setOutput(compr);

    err = deflater.deflate(Z_FULL_FLUSH);
    assertEquals(Z_OK, err);

    compr[3] = (byte) (compr[3] + 1);
    deflater.avail_in = hello.length - 3;

    err = deflater.deflate(Z_FINISH);
    assertEquals(Z_STREAM_END, err);
    int comprLen = (int) deflater.total_out;

    err = deflater.end();
    assertEquals(Z_OK, err);

    err = inflater.init();
    assertEquals(Z_OK, err);

    inflater.setInput(compr);
    inflater.avail_in = 2;

    inflater.setOutput(uncompr);

    err = inflater.inflate(JZlib.Z_NO_FLUSH);
    assertEquals(Z_OK, err);

    inflater.avail_in = comprLen - 2;
    err = inflater.sync();

    err = inflater.inflate(Z_FINISH);
    assertEquals(Z_DATA_ERROR, err);

    err = inflater.end();
    assertEquals(Z_OK, err);

    int total_out = (int) inflater.total_out;
    byte[] actual = new byte[total_out];
    System.arraycopy(uncompr, 0, actual, 0, total_out);

    assertEquals(new String(hello, UTF_8), "hel" + new String(actual, UTF_8));
  }

  @Test
  public void testInflaterCanInflateGzipData() {
    byte[] hello = "foo".getBytes(UTF_8);
    byte[] data = {(byte) 0x1f, (byte) 0x8b, (byte) 0x08, (byte) 0x18, (byte) 0x08, (byte) 0xeb,
        (byte) 0x7a, (byte) 0x0b, (byte) 0x00, (byte) 0x0b, (byte) 0x58, (byte) 0x00, (byte) 0x59,
        (byte) 0x00, (byte) 0x4b, (byte) 0xcb, (byte) 0xcf, (byte) 0x07, (byte) 0x00, (byte) 0x21,
        (byte) 0x65, (byte) 0x73, (byte) 0x8c, (byte) 0x03, (byte) 0x00, (byte) 0x00, (byte) 0x00};

    err = inflater.init(15 + 32);
    assertEquals(Z_OK, err);

    inflater.setInput(data);
    inflater.setOutput(uncompr);

    int comprLen = data.length;

    boolean loop = true;
    while (inflater.total_out < uncomprLen && inflater.total_in < comprLen && loop) {
      err = inflater.inflate(Z_NO_FLUSH);
      if (err == Z_STREAM_END)
        loop = false;
      else
        assertEquals(Z_OK, err);
    }

    err = inflater.end();
    assertEquals(Z_OK, err);

    int total_out = (int) inflater.total_out;
    byte[] actual = new byte[total_out];
    System.arraycopy(uncompr, 0, actual, 0, total_out);

    assertArrayEquals(hello, actual);
  }

  @Test
  public void testInflaterAndDeflaterCanSupportGzipData() {
    byte[] data = "hello, hello!".getBytes(UTF_8);

    err = deflater.init(Z_DEFAULT_COMPRESSION, 15 + 16);
    assertEquals(Z_OK, err);

    deflater.setInput(data);
    deflater.setOutput(compr);

    while (deflater.total_in < data.length && deflater.total_out < comprLen) {
      deflater.avail_in = 1;
      deflater.avail_out = 1;
      err = deflater.deflate(Z_NO_FLUSH);
      assertEquals(Z_OK, err);
    }

    do {
      deflater.avail_out = 1;
      err = deflater.deflate(Z_FINISH);
    } while (err != Z_STREAM_END);

    err = deflater.end();
    assertEquals(Z_OK, err);

    inflater.setInput(compr);
    inflater.setOutput(uncompr);

    err = inflater.init(15 + 32);
    assertEquals(Z_OK, err);

    boolean loop = true;
    while (inflater.total_out < uncomprLen && inflater.total_in < comprLen && loop) {
      inflater.avail_in = 1; // force small buffers
      inflater.avail_out = 1; // force small buffers
      err = inflater.inflate(Z_NO_FLUSH);
      if (err == Z_STREAM_END)
        loop = false;
      else
        assertEquals(Z_OK, err);
    }

    err = inflater.end();
    assertEquals(Z_OK, err);

    int total_out = (int) inflater.total_out;
    byte[] actual = new byte[total_out];
    System.arraycopy(uncompr, 0, actual, 0, total_out);

    assertArrayEquals(data, actual);
  }
}
