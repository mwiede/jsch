package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;

public class KeyExchangeTest {

  private final Random random = new Random();
  private final KeyExchange kex = new TestKex();

  @Test
  public void testNormalize0() {
    byte[] secret = new byte[0];
    doNormalize(secret);
  }

  @Test
  public void testNormalize1() {
    KeyExchange kex = new TestKex();
    byte[] secret = new byte[1];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      doNormalize(secret);
    }
  }

  @Test
  public void testNormalize2() {
    KeyExchange kex = new TestKex();
    byte[] secret = new byte[2];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      for (int j = 0; j <= 0xff; j++) {
        secret[1] = (byte) j;
        doNormalize(secret);
      }
    }
  }

  @Test
  public void testNormalize3() {
    KeyExchange kex = new TestKex();
    byte[] secret = new byte[3];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      for (int j = 0; j <= 0xff; j++) {
        secret[1] = (byte) j;
        for (int k = 0; k <= 0xff; k++) {
          secret[2] = (byte) k;
          doNormalize(secret);
        }
      }
    }
  }

  @Test
  public void testNormalizeRandom() {
    KeyExchange kex = new TestKex();
    for (int i = 0; i < 1000000; i++) {
      byte[] secret = new byte[64];
      random.nextBytes(secret);
      doNormalize(secret);
    }
  }

  @Test
  public void testEncodeAsMPInt1() {
    KeyExchange kex = new TestKex();
    byte[] secret = new byte[1];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      doEncodeAsMPInt(secret);
    }
  }

  @Test
  public void testEncodeAsMPInt2() {
    KeyExchange kex = new TestKex();
    byte[] secret = new byte[2];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      for (int j = 0; j <= 0xff; j++) {
        secret[1] = (byte) j;
        doEncodeAsMPInt(secret);
      }
    }
  }

  @Test
  public void testEncodeAsMPInt3() {
    KeyExchange kex = new TestKex();
    byte[] secret = new byte[3];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      for (int j = 0; j <= 0xff; j++) {
        secret[1] = (byte) j;
        for (int k = 0; k <= 0xff; k++) {
          secret[2] = (byte) k;
          doEncodeAsMPInt(secret);
        }
      }
    }
  }

  @Test
  public void testEncodeAsMPIntRandom() {
    KeyExchange kex = new TestKex();
    for (int i = 0; i < 1000000; i++) {
      byte[] secret = new byte[64];
      random.nextBytes(secret);
      doEncodeAsMPInt(secret);
    }
  }

  @Test
  public void testEncodeAsString0() {
    KeyExchange kex = new TestKex();
    byte[] secret = new byte[0];
    doEncodeAsString(secret);
  }

  @Test
  public void testEncodeAsString1() {
    KeyExchange kex = new TestKex();
    byte[] secret = new byte[1];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      doEncodeAsString(secret);
    }
  }

  @Test
  public void testEncodeAsString2() {
    KeyExchange kex = new TestKex();
    byte[] secret = new byte[2];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      for (int j = 0; j <= 0xff; j++) {
        secret[1] = (byte) j;
        doEncodeAsString(secret);
      }
    }
  }

  @Test
  public void testEncodeAsString3() {
    KeyExchange kex = new TestKex();
    byte[] secret = new byte[3];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      for (int j = 0; j <= 0xff; j++) {
        secret[1] = (byte) j;
        for (int k = 0; k <= 0xff; k++) {
          secret[2] = (byte) k;
          doEncodeAsString(secret);
        }
      }
    }
  }

  @Test
  public void testEncodeAsStringRandom() {
    KeyExchange kex = new TestKex();
    for (int i = 0; i < 1000000; i++) {
      byte[] secret = new byte[64];
      random.nextBytes(secret);
      doEncodeAsString(secret);
    }
  }

  private void doNormalize(byte[] secret) {
    byte[] expected = normalize(Arrays.copyOf(secret, secret.length));
    byte[] actual = kex.normalize(Arrays.copyOf(secret, secret.length));
    try {
      assertArrayEquals(expected, actual);
    } catch (Exception e) {
      System.out.println("  secret = " + Arrays.toString(secret));
      System.out.println("expected = " + Arrays.toString(expected));
      System.out.println("  actual = " + Arrays.toString(actual));
      throw e;
    }
  }

  // Copy of old implementation
  private static byte[] normalize(byte[] secret) {
    if (secret.length > 1 && secret[0] == 0 && (secret[1] & 0x80) == 0) {
      byte[] tmp = new byte[secret.length - 1];
      System.arraycopy(secret, 1, tmp, 0, tmp.length);
      Util.bzero(secret);
      return normalize(tmp);
    } else {
      return secret;
    }
  }

  private void doEncodeAsMPInt(byte[] secret) {
    Buffer b = new Buffer();
    b.putMPInt(secret);
    byte[] expected = new byte[b.getLength()];
    b.getByte(expected);
    byte[] actual = kex.encodeAsMPInt(Arrays.copyOf(secret, secret.length));
    try {
      assertArrayEquals(expected, actual);
    } catch (Throwable t) {
      System.out.println("  secret = " + Arrays.toString(secret));
      System.out.println("expected = " + Arrays.toString(expected));
      System.out.println("  actual = " + Arrays.toString(actual));
      throw t;
    }
  }

  private void doEncodeAsString(byte[] secret) {
    Buffer b = new Buffer();
    b.putString(secret);
    byte[] expected = new byte[b.getLength()];
    b.getByte(expected);
    byte[] actual = kex.encodeAsString(Arrays.copyOf(secret, secret.length));
    try {
      assertArrayEquals(expected, actual);
    } catch (Throwable t) {
      System.out.println("  secret = " + Arrays.toString(secret));
      System.out.println("expected = " + Arrays.toString(expected));
      System.out.println("  actual = " + Arrays.toString(actual));
      throw t;
    }
  }

  static class TestKex extends KeyExchange {

    @Override
    public void init(Session session, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C)
        throws Exception {
      throw new UnsupportedOperationException("Not supported");
    }

    @Override
    public boolean next(Buffer buf) throws Exception {
      throw new UnsupportedOperationException("Not supported");
    }

    @Override
    public int getState() {
      throw new UnsupportedOperationException("Not supported");
    }
  }
}
