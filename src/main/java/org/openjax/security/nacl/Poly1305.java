/* Copyright (c) 2019 OpenJAX
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * You should have received a copy of The MIT License (MIT) along with this
 * program. If not, see <http://opensource.org/licenses/MIT/>.
 */

package org.openjax.security.nacl;

/**
 * Port of Andrew Moon's Poly1305-donna-16. Public domain.
 * https://github.com/floodyberry/poly1305-donna
 */
public class Poly1305 {
  private final byte[] buffer;
  private final int[] r;
  private final int[] h;
  private final int[] pad;
  private int leftover;
  private int fin;

  public Poly1305(final byte[] key) {
    this.buffer = new byte[16];
    this.r = new int[10];
    this.h = new int[10];
    this.pad = new int[8];
    this.leftover = 0;
    this.fin = 0;

    final int t0;
    final int t1;
    final int t2;
    final int t3;
    final int t4;
    final int t5;
    final int t6;
    final int t7;
    t0 = key[0] & 0xff | (key[1] & 0xff) << 8;
    this.r[0] = t0 & 0x1fff;
    t1 = key[2] & 0xff | (key[3] & 0xff) << 8;
    this.r[1] = ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
    t2 = key[4] & 0xff | (key[5] & 0xff) << 8;
    this.r[2] = ((t1 >>> 10) | (t2 << 6)) & 0x1f03;
    t3 = key[6] & 0xff | (key[7] & 0xff) << 8;
    this.r[3] = ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
    t4 = key[8] & 0xff | (key[9] & 0xff) << 8;
    this.r[4] = ((t3 >>> 4) | (t4 << 12)) & 0x00ff;
    this.r[5] = ((t4 >>> 1)) & 0x1ffe;
    t5 = key[10] & 0xff | (key[11] & 0xff) << 8;
    this.r[6] = ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
    t6 = key[12] & 0xff | (key[13] & 0xff) << 8;
    this.r[7] = ((t5 >>> 11) | (t6 << 5)) & 0x1f81;
    t7 = key[14] & 0xff | (key[15] & 0xff) << 8;
    this.r[8] = ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
    this.r[9] = ((t7 >>> 5)) & 0x007f;

    this.pad[0] = key[16] & 0xff | (key[17] & 0xff) << 8;
    this.pad[1] = key[18] & 0xff | (key[19] & 0xff) << 8;
    this.pad[2] = key[20] & 0xff | (key[21] & 0xff) << 8;
    this.pad[3] = key[22] & 0xff | (key[23] & 0xff) << 8;
    this.pad[4] = key[24] & 0xff | (key[25] & 0xff) << 8;
    this.pad[5] = key[26] & 0xff | (key[27] & 0xff) << 8;
    this.pad[6] = key[28] & 0xff | (key[29] & 0xff) << 8;
    this.pad[7] = key[30] & 0xff | (key[31] & 0xff) << 8;
  }

  Poly1305 blocks(final byte[] m, int mpos, int bytes) {
    final int hibit = this.fin != 0 ? 0 : (1 << 11);
    int t0, t1, t2, t3, t4, t5, t6, t7, c;
    int d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;
    int h0 = this.h[0], h1 = this.h[1], h2 = this.h[2], h3 = this.h[3], h4 = this.h[4], h5 = this.h[5], h6 = this.h[6], h7 = this.h[7], h8 = this.h[8], h9 = this.h[9];
    final int r0 = this.r[0];
    final int r1 = this.r[1];
    final int r2 = this.r[2];
    final int r3 = this.r[3];
    final int r4 = this.r[4];
    final int r5 = this.r[5];
    final int r6 = this.r[6];
    final int r7 = this.r[7];
    final int r8 = this.r[8];
    final int r9 = this.r[9];
    while (bytes >= 16) {
      t0 = m[mpos + 0] & 0xff | (m[mpos + 1] & 0xff) << 8;
      h0 += t0 & 0x1fff;
      t1 = m[mpos + 2] & 0xff | (m[mpos + 3] & 0xff) << 8;
      h1 += ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
      t2 = m[mpos + 4] & 0xff | (m[mpos + 5] & 0xff) << 8;
      h2 += ((t1 >>> 10) | (t2 << 6)) & 0x1fff;
      t3 = m[mpos + 6] & 0xff | (m[mpos + 7] & 0xff) << 8;
      h3 += ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
      t4 = m[mpos + 8] & 0xff | (m[mpos + 9] & 0xff) << 8;
      h4 += ((t3 >>> 4) | (t4 << 12)) & 0x1fff;
      h5 += ((t4 >>> 1)) & 0x1fff;
      t5 = m[mpos + 10] & 0xff | (m[mpos + 11] & 0xff) << 8;
      h6 += ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
      t6 = m[mpos + 12] & 0xff | (m[mpos + 13] & 0xff) << 8;
      h7 += ((t5 >>> 11) | (t6 << 5)) & 0x1fff;
      t7 = m[mpos + 14] & 0xff | (m[mpos + 15] & 0xff) << 8;
      h8 += ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
      h9 += ((t7 >>> 5)) | hibit;

      c = 0;

      d0 = c;
      d0 += h0 * r0;
      d0 += h1 * (5 * r9);
      d0 += h2 * (5 * r8);
      d0 += h3 * (5 * r7);
      d0 += h4 * (5 * r6);
      c = d0 >>> 13;
      d0 &= 0x1fff;
      d0 += h5 * (5 * r5);
      d0 += h6 * (5 * r4);
      d0 += h7 * (5 * r3);
      d0 += h8 * (5 * r2);
      d0 += h9 * (5 * r1);
      c += d0 >>> 13;
      d0 &= 0x1fff;

      d1 = c;
      d1 += h0 * r1;
      d1 += h1 * r0;
      d1 += h2 * (5 * r9);
      d1 += h3 * (5 * r8);
      d1 += h4 * (5 * r7);
      c = d1 >>> 13;
      d1 &= 0x1fff;
      d1 += h5 * (5 * r6);
      d1 += h6 * (5 * r5);
      d1 += h7 * (5 * r4);
      d1 += h8 * (5 * r3);
      d1 += h9 * (5 * r2);
      c += d1 >>> 13;
      d1 &= 0x1fff;

      d2 = c;
      d2 += h0 * r2;
      d2 += h1 * r1;
      d2 += h2 * r0;
      d2 += h3 * (5 * r9);
      d2 += h4 * (5 * r8);
      c = d2 >>> 13;
      d2 &= 0x1fff;
      d2 += h5 * (5 * r7);
      d2 += h6 * (5 * r6);
      d2 += h7 * (5 * r5);
      d2 += h8 * (5 * r4);
      d2 += h9 * (5 * r3);
      c += d2 >>> 13;
      d2 &= 0x1fff;

      d3 = c;
      d3 += h0 * r3;
      d3 += h1 * r2;
      d3 += h2 * r1;
      d3 += h3 * r0;
      d3 += h4 * (5 * r9);
      c = d3 >>> 13;
      d3 &= 0x1fff;
      d3 += h5 * (5 * r8);
      d3 += h6 * (5 * r7);
      d3 += h7 * (5 * r6);
      d3 += h8 * (5 * r5);
      d3 += h9 * (5 * r4);
      c += d3 >>> 13;
      d3 &= 0x1fff;

      d4 = c;
      d4 += h0 * r4;
      d4 += h1 * r3;
      d4 += h2 * r2;
      d4 += h3 * r1;
      d4 += h4 * r0;
      c = d4 >>> 13;
      d4 &= 0x1fff;
      d4 += h5 * (5 * r9);
      d4 += h6 * (5 * r8);
      d4 += h7 * (5 * r7);
      d4 += h8 * (5 * r6);
      d4 += h9 * (5 * r5);
      c += d4 >>> 13;
      d4 &= 0x1fff;

      d5 = c;
      d5 += h0 * r5;
      d5 += h1 * r4;
      d5 += h2 * r3;
      d5 += h3 * r2;
      d5 += h4 * r1;
      c = d5 >>> 13;
      d5 &= 0x1fff;
      d5 += h5 * r0;
      d5 += h6 * (5 * r9);
      d5 += h7 * (5 * r8);
      d5 += h8 * (5 * r7);
      d5 += h9 * (5 * r6);
      c += d5 >>> 13;
      d5 &= 0x1fff;

      d6 = c;
      d6 += h0 * r6;
      d6 += h1 * r5;
      d6 += h2 * r4;
      d6 += h3 * r3;
      d6 += h4 * r2;
      c = d6 >>> 13;
      d6 &= 0x1fff;
      d6 += h5 * r1;
      d6 += h6 * r0;
      d6 += h7 * (5 * r9);
      d6 += h8 * (5 * r8);
      d6 += h9 * (5 * r7);
      c += d6 >>> 13;
      d6 &= 0x1fff;

      d7 = c;
      d7 += h0 * r7;
      d7 += h1 * r6;
      d7 += h2 * r5;
      d7 += h3 * r4;
      d7 += h4 * r3;
      c = d7 >>> 13;
      d7 &= 0x1fff;
      d7 += h5 * r2;
      d7 += h6 * r1;
      d7 += h7 * r0;
      d7 += h8 * (5 * r9);
      d7 += h9 * (5 * r8);
      c += d7 >>> 13;
      d7 &= 0x1fff;

      d8 = c;
      d8 += h0 * r8;
      d8 += h1 * r7;
      d8 += h2 * r6;
      d8 += h3 * r5;
      d8 += h4 * r4;
      c = d8 >>> 13;
      d8 &= 0x1fff;
      d8 += h5 * r3;
      d8 += h6 * r2;
      d8 += h7 * r1;
      d8 += h8 * r0;
      d8 += h9 * (5 * r9);
      c += d8 >>> 13;
      d8 &= 0x1fff;

      d9 = c;
      d9 += h0 * r9;
      d9 += h1 * r8;
      d9 += h2 * r7;
      d9 += h3 * r6;
      d9 += h4 * r5;
      c = d9 >>> 13;
      d9 &= 0x1fff;
      d9 += h5 * r4;
      d9 += h6 * r3;
      d9 += h7 * r2;
      d9 += h8 * r1;
      d9 += h9 * r0;
      c += d9 >>> 13;
      d9 &= 0x1fff;

      c += c << 2;
      c += d0;
      d0 = c & 0x1fff;
      c >>>= 13;
      d1 += c;

      h0 = d0;
      h1 = d1;
      h2 = d2;
      h3 = d3;
      h4 = d4;
      h5 = d5;
      h6 = d6;
      h7 = d7;
      h8 = d8;
      h9 = d9;

      mpos += 16;
      bytes -= 16;
    }

    this.h[0] = h0;
    this.h[1] = h1;
    this.h[2] = h2;
    this.h[3] = h3;
    this.h[4] = h4;
    this.h[5] = h5;
    this.h[6] = h6;
    this.h[7] = h7;
    this.h[8] = h8;
    this.h[9] = h9;

    return this;
  }

  public Poly1305 finish(final byte[] mac, final int macpos) {
    final int[] g = new int[10];
    int c, mask, f, i;

    if (this.leftover != 0) {
      i = this.leftover;
      this.buffer[i++] = 1;
      for (; i < 16; ++i)
        this.buffer[i] = 0;

      this.fin = 1;
      this.blocks(this.buffer, 0, 16);
    }

    c = this.h[1] >>> 13;
    this.h[1] &= 0x1fff;
    for (i = 2; i < 10; ++i) {
      this.h[i] += c;
      c = this.h[i] >>> 13;
      this.h[i] &= 0x1fff;
    }

    this.h[0] += c * 5;
    c = this.h[0] >>> 13;
    this.h[0] &= 0x1fff;
    this.h[1] += c;
    c = this.h[1] >>> 13;
    this.h[1] &= 0x1fff;
    this.h[2] += c;

    g[0] = this.h[0] + 5;
    c = g[0] >>> 13;
    g[0] &= 0x1fff;
    for (i = 1; i < 10; ++i) {
      g[i] = this.h[i] + c;
      c = g[i] >>> 13;
      g[i] &= 0x1fff;
    }

    g[9] -= 1 << 13;
    g[9] &= 0xffff;

    /*
     * backport from tweetnacl-fast.js
     * https://github.com/dchest/tweetnacl-js/releases/tag/v0.14.3 <<< "The
     * issue was not properly detecting if st->h was >= 2^130 - 5, coupled
     * with [testing mistake] not catching the failure. The chance of the bug
     * affecting anything in the real world is essentially zero luckily, but
     * it's good to have it fixed." >>>
     */
    // change mask = (g[9] >>> ((2 * 8) - 1)) - 1; to as
    mask = (c ^ 1) - 1;
    mask &= 0xffff;

    for (i = 0; i < 10; ++i)
      g[i] &= mask;

    mask = ~mask;
    for (i = 0; i < 10; ++i)
      this.h[i] = (this.h[i] & mask) | g[i];

    this.h[0] = ((this.h[0]) | (this.h[1] << 13)) & 0xffff;
    this.h[1] = ((this.h[1] >>> 3) | (this.h[2] << 10)) & 0xffff;
    this.h[2] = ((this.h[2] >>> 6) | (this.h[3] << 7)) & 0xffff;
    this.h[3] = ((this.h[3] >>> 9) | (this.h[4] << 4)) & 0xffff;
    this.h[4] = ((this.h[4] >>> 12) | (this.h[5] << 1) | (this.h[6] << 14)) & 0xffff;
    this.h[5] = ((this.h[6] >>> 2) | (this.h[7] << 11)) & 0xffff;
    this.h[6] = ((this.h[7] >>> 5) | (this.h[8] << 8)) & 0xffff;
    this.h[7] = ((this.h[8] >>> 8) | (this.h[9] << 5)) & 0xffff;

    f = this.h[0] + this.pad[0];
    this.h[0] = f & 0xffff;
    for (i = 1; i < 8; ++i) {
      f = this.h[i] + this.pad[i] + (f >>> 16);
      this.h[i] = f & 0xffff;
    }

    mac[macpos + 0] = (byte)(this.h[0] & 0xff);
    mac[macpos + 1] = (byte)((this.h[0] >>> 8) & 0xff);
    mac[macpos + 2] = (byte)(this.h[1] & 0xff);
    mac[macpos + 3] = (byte)((this.h[1] >>> 8) & 0xff);
    mac[macpos + 4] = (byte)(this.h[2] & 0xff);
    mac[macpos + 5] = (byte)((this.h[2] >>> 8) & 0xff);
    mac[macpos + 6] = (byte)(this.h[3] & 0xff);
    mac[macpos + 7] = (byte)((this.h[3] >>> 8) & 0xff);
    mac[macpos + 8] = (byte)(this.h[4] & 0xff);
    mac[macpos + 9] = (byte)((this.h[4] >>> 8) & 0xff);
    mac[macpos + 10] = (byte)(this.h[5] & 0xff);
    mac[macpos + 11] = (byte)((this.h[5] >>> 8) & 0xff);
    mac[macpos + 12] = (byte)(this.h[6] & 0xff);
    mac[macpos + 13] = (byte)((this.h[6] >>> 8) & 0xff);
    mac[macpos + 14] = (byte)(this.h[7] & 0xff);
    mac[macpos + 15] = (byte)((this.h[7] >>> 8) & 0xff);

    return this;
  }

  public Poly1305 update(final byte[] m, int mpos, int bytes) {
    int i, want;
    if (this.leftover != 0) {
      want = (16 - this.leftover);
      if (want > bytes)
        want = bytes;

      for (i = 0; i < want; ++i)
        this.buffer[this.leftover + i] = m[mpos + i];

      bytes -= want;
      mpos += want;
      this.leftover += want;
      if (this.leftover < 16)
        return this;

      this.blocks(buffer, 0, 16);
      this.leftover = 0;
    }

    if (bytes >= 16) {
      want = bytes - (bytes % 16);
      this.blocks(m, mpos, want);
      mpos += want;
      bytes -= want;
    }

    if (bytes != 0) {
      for (i = 0; i < bytes; ++i)
        this.buffer[this.leftover + i] = m[mpos + i];

      this.leftover += bytes;
    }

    return this;
  }
}
