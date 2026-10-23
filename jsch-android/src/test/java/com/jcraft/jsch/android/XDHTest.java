// SPDX-License-Identifier: BSD-3-Clause
package com.jcraft.jsch.android;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jcraft.jsch.JSch;
import org.junit.jupiter.api.Test;

class XDHTest {
  @Test
  void x25519AgreesWithPeer() throws Exception {
    AndroidXDH first = new AndroidXDH();
    AndroidXDH second = new AndroidXDH();
    first.init("X25519", 32);
    second.init("X25519", 32);

    assertEquals(32, first.getQ().length);
    assertTrue(first.validate(second.getQ()));
    assertFalse(first.validate(new byte[31]));
    assertArrayEquals(first.getSecret(second.getQ()), second.getSecret(first.getQ()));
  }

  @Test
  void x448FallsBackToBouncyCastle() throws Exception {
    AndroidXDH first = new AndroidXDH();
    AndroidXDH second = new AndroidXDH();
    first.init("X448", 56);
    second.init("X448", 56);

    assertEquals(56, first.getQ().length);
    assertArrayEquals(first.getSecret(second.getQ()), second.getSecret(first.getQ()));
  }

  @Test
  void configurationKeepsEd448WhenUnsupported() {
    String previous = JSch.getConfig("ssh-ed448");
    try {
      AndroidJSch.configure();
      if (!AndroidJSch.hasServices("Ed448", "Signature", "KeyFactory")) {
        assertEquals(previous, JSch.getConfig("ssh-ed448"));
      }
    } finally {
      JSch.setConfig("ssh-ed448", previous);
    }
  }
}
