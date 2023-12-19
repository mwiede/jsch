package com.jcraft.jsch.jzlib;

import static com.jcraft.jsch.jzlib.JZlib.*;
import static com.jcraft.jsch.jzlib.Package.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class WrapperTypeTest {
  private final byte[] data = "hello, hello!".getBytes(UTF_8);

  private final int comprLen = 40000;
  private final int uncomprLen = comprLen;
  private byte[] compr;
  private byte[] uncompr;
  private int err;

  private final List<Case> cases = Arrays.asList(
      /* success fail */
      new Case(W_ZLIB, Arrays.asList(W_ZLIB, W_ANY), Arrays.asList(W_GZIP, W_NONE)),
      new Case(W_GZIP, Arrays.asList(W_GZIP, W_ANY), Arrays.asList(W_ZLIB, W_NONE)),
      new Case(W_NONE, Arrays.asList(W_NONE, W_ANY), Arrays.asList(W_ZLIB, W_GZIP)));

  @BeforeEach
  public void before() {
    compr = new byte[comprLen];
    uncompr = new byte[uncomprLen];

    err = Z_OK;
  }

  @AfterEach
  public void after() {}

  @Test
  public void testDeflaterCanDetectDataTypeOfInput() {
    byte[] buf = compr;

    cases.forEach(uncheckedConsumer(c -> {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      Deflater deflater = new Deflater(Z_DEFAULT_COMPRESSION, DEF_WBITS, 9, c.iflag);
      DeflaterOutputStream gos = new DeflaterOutputStream(baos, deflater);
      readArray(data, gos, buf);
      gos.close();

      byte[] deflated = baos.toByteArray();

      c.good.stream().map(uncheckedFunction(w -> {
        ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
        Inflater inflater = new Inflater(w);
        readIS(new InflaterInputStream(new ByteArrayInputStream(deflated), inflater), baos2, buf);
        byte[] data1 = baos2.toByteArray();
        assertEquals(data.length, data1.length);
        assertArrayEquals(data, data1);
        return new Tuple(inflater.avail_in, inflater.avail_out, inflater.total_in,
            inflater.total_out);
      })).reduce((x, y) -> {
        assertEquals(y, x);
        return x;
      });

      c.bad.forEach(uncheckedConsumer(w -> {
        ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
        Inflater inflater = new Inflater(w);
        assertThrows(IOException.class,
            () -> readIS(new InflaterInputStream(new ByteArrayInputStream(deflated), inflater),
                baos2, buf));
      }));
    }));
  }

  @Test
  public void testZStreamCanDetectDataTypeOfInput() {
    cases.forEach(c -> {
      ZStream deflater = new ZStream();

      err = deflater.deflateInit(Z_BEST_SPEED, DEF_WBITS, 9, c.iflag);
      assertEquals(Z_OK, err);

      deflate(deflater, data, compr);

      c.good.forEach(w -> {
        ZStream inflater = inflate(compr, uncompr, w);
        int total_out = (int) inflater.total_out;
        assertEquals(new String(data, UTF_8), new String(uncompr, 0, total_out, UTF_8));
      });

      c.bad.forEach(w -> {
        inflate_fail(compr, uncompr, w);
      });
    });
  }

  @Test
  public void testDeflaterCanSupportWbitsPlus32() {

    Deflater deflater = new Deflater();
    err = deflater.init(Z_BEST_SPEED, DEF_WBITS, 9);
    assertEquals(Z_OK, err);

    deflate(deflater, data, compr);

    Inflater inflater = new Inflater();
    err = inflater.init(DEF_WBITS + 32);
    assertEquals(Z_OK, err);

    inflater.setInput(compr);

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
    assertEquals(new String(data, UTF_8), new String(uncompr, 0, total_out, UTF_8));

    deflater = new Deflater();
    err = deflater.init(Z_BEST_SPEED, DEF_WBITS + 16, 9);
    assertEquals(Z_OK, err);

    deflate(deflater, data, compr);

    inflater = new Inflater();
    err = inflater.init(DEF_WBITS + 32);
    assertEquals(Z_OK, err);

    inflater.setInput(compr);

    loop = true;
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

    total_out = (int) inflater.total_out;
    assertEquals(new String(data, UTF_8), new String(uncompr, 0, total_out, UTF_8));
  }

  private void deflate(ZStream deflater, byte[] data, byte[] compr) {
    deflater.setInput(data);
    deflater.setOutput(compr);

    err = deflater.deflate(JZlib.Z_FINISH);
    assertEquals(Z_STREAM_END, err);

    err = deflater.end();
    assertEquals(Z_OK, err);
  }

  private ZStream inflate(byte[] compr, byte[] uncompr, WrapperType w) {
    ZStream inflater = new ZStream();
    err = inflater.inflateInit(w);
    assertEquals(Z_OK, err);

    inflater.setInput(compr);

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

    return inflater;
  }

  private void inflate_fail(byte[] compr, byte[] uncompr, WrapperType w) {
    ZStream inflater = new ZStream();

    err = inflater.inflateInit(w);
    assertEquals(Z_OK, err);

    inflater.setInput(compr);

    boolean loop = true;
    while (loop) {
      inflater.setOutput(uncompr);
      err = inflater.inflate(Z_NO_FLUSH);
      if (err == Z_STREAM_END)
        loop = false;
      else {
        assertEquals(Z_DATA_ERROR, err);
        loop = false;
      }
    }
  }

  static class Case {
    final WrapperType iflag;
    final List<WrapperType> good;
    final List<WrapperType> bad;

    Case(WrapperType iflag, List<WrapperType> good, List<WrapperType> bad) {
      this.iflag = iflag;
      this.good = good;
      this.bad = bad;
    }
  }

  static class Tuple {
    private final int a;
    private final int b;
    private final long c;
    private final long d;

    Tuple(int a, int b, long c, long d) {
      this.a = a;
      this.b = b;
      this.c = c;
      this.d = d;
    }

    @Override
    public boolean equals(Object obj) {
      if (!(obj instanceof Tuple))
        return false;
      else if (a != ((Tuple) obj).a)
        return false;
      else if (b != ((Tuple) obj).b)
        return false;
      else if (c != ((Tuple) obj).c)
        return false;
      else if (d != ((Tuple) obj).d)
        return false;
      else
        return true;
    }

    @Override
    public int hashCode() {
      return Objects.hash(a, b, c, d);
    }
  }
}
