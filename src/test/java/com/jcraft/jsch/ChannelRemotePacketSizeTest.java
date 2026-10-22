package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class ChannelRemotePacketSizeTest {

  private static final int MAX = Session.PACKET_MAX_SIZE - 4096;

  private static int apply(int size) {
    Channel c = new ChannelSession();
    c.setRemotePacketSize(size);
    return c.rmpsize;
  }

  @Test
  void normalValueIsKept() {
    assertEquals(32768, apply(32768));
    assertEquals(MAX, apply(MAX));
  }

  @Test
  void oversizedValueIsCapped() {
    assertEquals(MAX, apply(MAX + 1));
    assertEquals(MAX, apply(67108864));
    assertEquals(MAX, apply(Integer.MAX_VALUE));
  }

  @Test
  void negativeValueIsCapped() {
    assertEquals(MAX, apply(-1));
    assertEquals(MAX, apply(Integer.MIN_VALUE));
  }
}
