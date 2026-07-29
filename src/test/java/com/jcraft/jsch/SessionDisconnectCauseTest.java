package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SessionDisconnectCauseTest {

  private static Session newSession() throws Exception {
    return new Session(new JSch(), null, null, 0);
  }

  private static Session newConnectedSession(InputStream in) throws Exception {
    Session s = newSession();
    IO io = new IO();
    io.setInputStream(in);
    s.io = io;
    s.isConnected = true;
    return s;
  }

  @Test
  @DisplayName("null before the session was ever connected")
  void nullOnFreshSession() throws Exception {
    assertNull(newSession().getDisconnectCause());
  }

  @Test
  @DisplayName("null while the session is still connected")
  void nullWhileConnected() throws Exception {
    IOException error = new IOException("connection reset");
    Session s = newSession();
    s.disconnectCause = error;
    s.isConnected = true;

    assertNull(s.getDisconnectCause());

    s.isConnected = false;
    assertSame(error, s.getDisconnectCause());
  }

  @Test
  @DisplayName("records the exception that made the read loop exit")
  void readLoopFailureIsRecorded() throws Exception {
    IOException error = new IOException("connection reset");
    Session s = newConnectedSession(new InputStream() {
      @Override
      public int read() throws IOException {
        throw error;
      }
    });

    s.run();

    assertSame(error, s.getDisconnectCause());
    assertFalse(s.isConnected());
  }

  @Test
  @DisplayName("a local disconnect() is not recorded as a cause")
  void localDisconnectIsNotRecorded() throws Exception {
    Session[] holder = new Session[1];
    Session s = newConnectedSession(new InputStream() {
      @Override
      public int read() throws IOException {
        // Mimic disconnect() closing a blocked read.
        holder[0].disconnect();
        throw new IOException("stream closed");
      }
    });
    holder[0] = s;

    s.run();

    assertNull(s.getDisconnectCause());
    assertFalse(s.isConnected());
  }

  @Test
  @DisplayName("cleared again by connect()")
  void clearedByConnect() throws Exception {
    Session s = newSession();
    s.disconnectCause = new IOException("previous session died");
    assertThrows(JSchException.class, () -> s.connect(1));
    assertNull(s.getDisconnectCause());
  }
}
