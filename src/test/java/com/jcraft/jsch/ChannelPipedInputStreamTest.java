package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;

public class ChannelPipedInputStreamTest {

  private static final int INITIAL_SIZE = 32 * 1024;
  private static final int MAX_SIZE = 256 * 1024;

  @Test
  public void testGrowingFullWrappedBufferKeepsAllBytes() throws Exception {
    Channel.MyPipedInputStream in = new Channel.MyPipedInputStream(INITIAL_SIZE, MAX_SIZE);
    Channel.PassiveOutputStream out = new Channel.PassiveOutputStream(in, true);
    byte[] first = filled(32 * 1024, (byte) 1);
    byte[] second = filled(20 * 1024, (byte) 2);
    byte[] third = filled(32 * 1024, (byte) 3);

    out.write(first, 0, first.length);
    readFully(in, new byte[20 * 1024]);
    // The buffer is now full and wrapped: in == out == 20 KiB.
    out.write(second, 0, second.length);
    // Growing the buffer must keep the 20 KiB written after the wrap.
    out.write(third, 0, third.length);

    byte[] expected = new byte[12 * 1024 + second.length + third.length];
    System.arraycopy(first, 20 * 1024, expected, 0, 12 * 1024);
    System.arraycopy(second, 0, expected, 12 * 1024, second.length);
    System.arraycopy(third, 0, expected, 12 * 1024 + second.length, third.length);
    assertEquals(expected.length, in.available());
    byte[] actual = new byte[expected.length];
    readFully(in, actual);
    assertArrayEquals(expected, actual);
  }

  @Test
  public void testPacketSizedWritesWithDrainingReadsKeepAllBytes() throws Exception {
    Channel.MyPipedInputStream in = new Channel.MyPipedInputStream(INITIAL_SIZE, MAX_SIZE);
    Channel.PassiveOutputStream out = new Channel.PassiveOutputStream(in, true);
    Random random = new Random(1);
    byte[] chunk = new byte[64 * 1024];
    long sent = 0;
    long received = 0;

    for (int step = 0; step < 10000; step++) {
      if (random.nextBoolean()) {
        int len = random.nextBoolean() ? 16 * 1024 : 32 * 1024;
        if (len > MAX_SIZE - in.available()) {
          continue;
        }
        for (int i = 0; i < len; i++) {
          chunk[i] = patternByte(sent + i);
        }
        out.write(chunk, 0, len);
        sent += len;
      } else if (in.available() > 0) {
        received += readAndVerify(in, chunk, received);
      }
    }
    while (in.available() > 0) {
      received += readAndVerify(in, chunk, received);
    }

    assertEquals(sent, received);
  }

  private static int readAndVerify(InputStream in, byte[] chunk, long position) throws IOException {
    int read = in.read(chunk, 0, chunk.length);
    for (int i = 0; i < read; i++) {
      if (chunk[i] != patternByte(position + i)) {
        fail("unexpected byte at stream position " + (position + i));
      }
    }
    return read;
  }

  private static byte patternByte(long position) {
    return (byte) (position % 251);
  }

  private static byte[] filled(int size, byte value) {
    byte[] bytes = new byte[size];
    Arrays.fill(bytes, value);
    return bytes;
  }

  private static void readFully(InputStream in, byte[] target) throws IOException {
    int done = 0;
    while (done < target.length) {
      done += in.read(target, done, target.length - done);
    }
  }
}
