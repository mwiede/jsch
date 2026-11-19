/*
 * Copyright (c) 2002-2018 ymnk, JCraft,Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions
 * and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided with
 * the distribution.
 *
 * 3. The names of the authors may not be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL JCRAFT, INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.jcraft.jsch;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;

/** A channel's bounded receive buffer. Only application reads return receive credit. */
final class ChannelInputStream extends InputStream {
  private final Channel channel;
  private byte[] buffer;
  private int head;
  private int size;
  private boolean finished;
  private boolean closed;

  ChannelInputStream(Channel channel) {
    this.channel = channel;
  }

  OutputStream sink() {
    return new Sink();
  }

  @Override
  public int read() throws IOException {
    byte[] one = new byte[1];
    return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
  }

  @Override
  public int read(byte[] bytes, int offset, int length) throws IOException {
    if (bytes == null)
      throw new NullPointerException("bytes");
    if (offset < 0 || length < 0 || length > bytes.length - offset)
      throw new IndexOutOfBoundsException();
    if (length == 0)
      return 0;
    int count;
    synchronized (this) {
      while (size == 0 && !finished && !closed) {
        try {
          wait();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          InterruptedIOException interrupted = new InterruptedIOException(
              "Interrupted while reading SSH channel " + channel.getId());
          interrupted.initCause(e);
          throw interrupted;
        }
      }
      if (closed)
        throw new IOException("SSH channel input stream is closed");
      if (size == 0)
        return -1;
      count = Math.min(length, size);
      int first = Math.min(count, buffer.length - head);
      System.arraycopy(buffer, head, bytes, offset, first);
      System.arraycopy(buffer, 0, bytes, offset + first, count - first);
      head = (head + count) % buffer.length;
      size -= count;
      if (size == 0 && finished)
        buffer = null;
    }
    // Never hold the buffer monitor across protocol I/O. Incoming DATA only copies
    // into this buffer; it never waits for a read or runs application code.
    channel.returnReceiveCredit(count);
    return count;
  }

  @Override
  public synchronized int available() throws IOException {
    if (closed)
      throw new IOException("SSH channel input stream is closed");
    return size;
  }

  @Override
  public void close() {
    boolean cancelChannel;
    synchronized (this) {
      cancelChannel = !finished && !closed;
      abort();
    }
    // Closing a stream whose EOF was received must leave the other stream's
    // final bytes available. Closing an active stream cancels its channel.
    if (cancelChannel)
      channel.disconnect();
  }

  synchronized void abort() {
    closed = true;
    finished = true;
    buffer = null;
    size = 0;
    head = 0;
    notifyAll();
  }

  final class Sink extends OutputStream {
    @Override
    public void write(int value) throws IOException {
      write(new byte[] {(byte) value}, 0, 1);
    }

    @Override
    public void write(byte[] bytes, int offset, int length) throws IOException {
      synchronized (ChannelInputStream.this) {
        if (closed || finished)
          throw new IOException("SSH channel input stream is closed");
        if (buffer == null)
          buffer = new byte[channel.getLocalWindowSizeMax()];
        if (length > buffer.length - size)
          throw new IOException("SSH channel DATA exceeds its receive window: pending=" + size
              + ", incoming=" + length + ", capacity=" + buffer.length);
        int tail = (head + size) % buffer.length;
        int first = Math.min(length, buffer.length - tail);
        System.arraycopy(bytes, offset, buffer, tail, first);
        System.arraycopy(bytes, offset + first, buffer, 0, length - first);
        size += length;
        ChannelInputStream.this.notifyAll();
      }
    }

    @Override
    public void close() {
      synchronized (ChannelInputStream.this) {
        finished = true;
        if (size == 0)
          buffer = null;
        ChannelInputStream.this.notifyAll();
      }
    }
  }
}
