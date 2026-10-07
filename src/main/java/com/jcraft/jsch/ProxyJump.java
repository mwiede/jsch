package com.jcraft.jsch;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Carries an SSH connection through one or more direct-tcpip channels, like OpenSSH's
 * {@code ProxyJump} ({@code ssh -J}).
 *
 * <p>
 * Each hop is a separate {@link Session} created by {@link JSch#getSession(String, String, int)}, so
 * it uses its own {@code Host} configuration and the {@link JSch} instance's settings, such as its
 * host-key repository. As with {@code ssh -J}, settings made on the target session itself, for
 * example {@code StrictHostKeyChecking} or a host-key repository, do not apply to the hops; to pin a
 * hop differently, connect it yourself and use {@link #through(Session)}. Hops never see the
 * target's {@link UserInfo} or password. Prompts from hops, for a password, a passphrase or a host-key
 * decision, go to the {@link Session#setProxyJumpUserInfo ProxyJump UserInfo} if one is set, each
 * prompt naming the hop it is for, as {@code ssh -J} asks for every hop in turn. Without one, hops
 * must authenticate without prompting, for example with keys from the identity repository.
 *
 * <p>
 * The whole chain shares one connect deadline: the largest {@code ConnectTimeout} of the target and
 * of every hop. Hops do not each get the full timeout.
 *
 * <p>
 * {@link #through(Session)} tunnels a session through a hop the application connects and
 * disconnects itself; several sessions may use one such hop.
 *
 * <p>
 * A proxy instance serves one session, which serializes {@link #connect} and {@link #close} on it.
 */
public final class ProxyJump implements ReadTimeoutProxy {
  private static final int DEFAULT_PORT = 22;
  private static final String URI_PREFIX = "ssh://";
  // A tunnelled SSH session needs a wider window than port forwarding; OpenSSH uses 2 MiB.
  private static final int CHANNEL_WINDOW_SIZE = 0x200000;
  private static final int CHANNEL_PACKET_SIZE = 0x8000;
  private static final int INITIAL_BUFFER_SIZE = 0x8000;

  private final Session target;
  private final List<Hop> hops;
  private final List<Session> sessions = new ArrayList<>();
  private volatile ChannelProxy destination;

  public ProxyJump(Session target, String specification) throws JSchException {
    this.target = target;
    this.hops = parse(specification);
  }

  /**
   * Returns a proxy that carries a session through a direct-tcpip channel of {@code hop}, which the
   * caller connects before and disconnects after use. Several sessions may share one hop, each with
   * its own proxy instance.
   */
  public static Proxy through(Session hop) {
    return new ChannelProxy(Objects.requireNonNull(hop, "hop"));
  }

  @Override
  public void connect(SocketFactory socketFactory, String host, int port, int timeout)
      throws JSchException {
    checkForCycle();
    try {
      Session previous = null;
      for (Hop hop : hops) {
        previous = createHop(hop, previous, socketFactory);
        sessions.add(previous);
      }
      int budget = connectBudget(timeout, sessions);
      long deadline = budget > 0 ? System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(budget) : 0;
      for (Session session : sessions) {
        session.connect(remaining(deadline));
      }
      ChannelProxy tunnel = new ChannelProxy(previous);
      destination = tunnel;
      tunnel.connect(socketFactory, host, port, remaining(deadline));
      // Bound each read of the target handshake; Session replaces this once it is authenticated.
      tunnel.setReadTimeout(budget);
    } catch (JSchException | RuntimeException e) {
      close();
      throw e;
    }
  }

  /**
   * Chains only nest through the first hop's own {@code ProxyJump} setting, which its
   * {@code Session} takes from the config repository. Following those settings from alias to alias,
   * without creating a session, finds a loop before anything is opened.
   */
  private void checkForCycle() throws JSchException {
    ConfigRepository repository = target.jsch.getConfigRepository();
    List<String> path = new ArrayList<>();
    String alias = hops.get(0).host;
    while (!path.contains(alias)) {
      path.add(alias);
      ConfigRepository.Config config = repository == null ? null : repository.getConfig(alias);
      String value = config == null ? null : config.getValue("ProxyJump");
      if (value == null || value.equalsIgnoreCase("none")) {
        return;
      }
      alias = parse(value).get(0).host;
    }
    path.add(alias);
    throw new JSchException("ProxyJump cycle: " + String.join(" -> ", path));
  }

  Session createHop(Hop hop, Session previous, SocketFactory socketFactory) throws JSchException {
    Session next =
        target.jsch.getSession(hop.user, hop.host, hop.port == 0 ? DEFAULT_PORT : hop.port);
    next.setUserInfo(target.getProxyJumpUserInfo());
    next.setProxyJumpUserInfo(target.getProxyJumpUserInfo());
    next.setDaemonThread(target.daemon_thread);
    next.setThreadFactory(target.getThreadFactory());
    if (target.getLogger() != target.jsch.getInstanceLogger()) {
      next.setLogger(target.getLogger());
    }
    if (hop.port != 0) {
      next.setPort(hop.port);
    }
    if (previous != null) {
      // Like ssh -J, only the first hop keeps a ProxyJump of its own Host config.
      next.setProxy(new ChannelProxy(previous));
    } else if (socketFactory != null) {
      next.setSocketFactory(socketFactory);
    }
    return next;
  }

  /** The largest connect timeout on the path, or 0 if none is set. */
  static int connectBudget(int timeout, List<Session> chain) {
    int budget = timeout;
    for (Session session : chain) {
      budget = Math.max(budget, session.getTimeout());
    }
    return budget;
  }

  private static int remaining(long deadline) throws JSchException {
    if (deadline == 0) {
      return 0;
    }
    long millis = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
    if (millis <= 0) {
      throw new JSchException("ProxyJump connect timed out");
    }
    return (int) Math.min(millis, Integer.MAX_VALUE);
  }

  @Override
  public InputStream getInputStream() {
    ChannelProxy tunnel = destination;
    return tunnel == null ? null : tunnel.getInputStream();
  }

  @Override
  public OutputStream getOutputStream() {
    ChannelProxy tunnel = destination;
    return tunnel == null ? null : tunnel.getOutputStream();
  }

  @Override
  public Socket getSocket() {
    return null;
  }

  @Override
  public void setReadTimeout(int timeout) throws JSchException {
    if (timeout < 0) {
      throw new JSchException("invalid timeout value");
    }
    ChannelProxy tunnel = destination;
    if (tunnel != null) {
      tunnel.setReadTimeout(timeout);
    }
  }

  @Override
  public void close() {
    ChannelProxy tunnel = destination;
    if (tunnel != null) {
      tunnel.close();
      destination = null;
    }
    for (int i = sessions.size() - 1; i >= 0; i--) {
      sessions.get(i).disconnect();
    }
    sessions.clear();
  }

  static List<Hop> parse(String specification) throws JSchException {
    if (specification == null || specification.isEmpty()) {
      throw new JSchException("ProxyJump requires at least one host");
    }
    List<Hop> result = new ArrayList<>();
    for (String item : specification.split(",", -1)) {
      try {
        result.add(parseHop(item));
      } catch (IllegalArgumentException e) {
        // The item is redacted and the cause dropped so a password-like value never leaks.
        throw new JSchException(
            "Invalid ProxyJump host: " + redact(item) + " (" + e.getMessage() + ")");
      }
    }
    return Collections.unmodifiableList(result);
  }

  /** Hides everything after a ':' in the user part, which may be a password. */
  static String redact(String item) {
    int start = item.startsWith(URI_PREFIX) ? URI_PREFIX.length() : 0;
    int at = item.lastIndexOf('@');
    int colon = item.indexOf(':', start);
    if (at < start || colon < 0 || colon > at) {
      return item;
    }
    return item.substring(0, colon) + ":***" + item.substring(at);
  }

  private static Hop parseHop(String item) {
    if (item.isEmpty()) {
      throw new IllegalArgumentException("empty host");
    }
    for (int i = 0; i < item.length(); i++) {
      if (Character.isWhitespace(item.charAt(i))) {
        throw new IllegalArgumentException("whitespace");
      }
    }
    return item.startsWith(URI_PREFIX) ? parseUriHop(item.substring(URI_PREFIX.length()))
        : parseHostHop(item);
  }

  /** Parses the part after {@code ssh://}, following OpenSSH's parse_uri(). */
  private static Hop parseUriHop(String rest) {
    int slash = rest.indexOf('/');
    if (slash >= 0 && slash != rest.length() - 1) {
      throw new IllegalArgumentException("URI path is not allowed");
    }
    String authority = slash >= 0 ? rest.substring(0, slash) : rest;
    if (authority.indexOf('?') >= 0 || authority.indexOf('#') >= 0) {
      throw new IllegalArgumentException("URI query or fragment is not allowed");
    }
    int at = authority.lastIndexOf('@');
    String user = null;
    if (at >= 0) {
      String userinfo = authority.substring(0, at);
      int params = userinfo.indexOf(';');
      if (params >= 0) {
        // OpenSSH ignores connection parameters such as ";fingerprint=..."
        userinfo = userinfo.substring(0, params);
      }
      if (userinfo.indexOf(':') >= 0) {
        throw new IllegalArgumentException("passwords are not supported");
      }
      user = percentDecode(userinfo);
    }
    return parseAddress(user, authority.substring(at + 1));
  }

  private static Hop parseHostHop(String item) {
    int at = item.lastIndexOf('@');
    return parseAddress(at < 0 ? null : item.substring(0, at), item.substring(at + 1));
  }

  private static Hop parseAddress(String user, String address) {
    if (user != null && user.isEmpty()) {
      throw new IllegalArgumentException("empty user");
    }
    String[] hostAndPort = address.startsWith("[") ? splitBracketed(address) : splitPlain(address);
    if (hostAndPort[0].isEmpty()) {
      throw new IllegalArgumentException("empty host");
    }
    return new Hop(user, hostAndPort[0], hostAndPort[1] == null ? 0 : parsePort(hostAndPort[1]));
  }

  /** Splits {@code [host]} or {@code [host]:port}; the port is null when absent. */
  private static String[] splitBracketed(String address) {
    int end = address.indexOf(']');
    if (end < 0 || (end + 1 < address.length() && address.charAt(end + 1) != ':')) {
      throw new IllegalArgumentException("malformed IPv6 address");
    }
    String port = end + 1 < address.length() ? address.substring(end + 2) : null;
    return new String[] {address.substring(1, end), port};
  }

  /** Splits {@code host} or {@code host:port}; the port is null when absent. */
  private static String[] splitPlain(String address) {
    int colon = address.indexOf(':');
    if (colon != address.lastIndexOf(':')) {
      throw new IllegalArgumentException("IPv6 addresses need brackets");
    }
    if (colon < 0) {
      return new String[] {address, null};
    }
    return new String[] {address.substring(0, colon), address.substring(colon + 1)};
  }

  private static int parsePort(String value) {
    int port;
    try {
      port = Integer.parseInt(value);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("bad port", e);
    }
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("bad port");
    }
    return port;
  }

  private static String percentDecode(String value) {
    if (value.indexOf('%') < 0) {
      return value;
    }
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    int i = 0;
    while (i < value.length()) {
      int percent = value.indexOf('%', i);
      if (percent < 0) {
        percent = value.length();
      }
      byte[] literal = value.substring(i, percent).getBytes(StandardCharsets.UTF_8);
      bytes.write(literal, 0, literal.length);
      if (percent == value.length()) {
        break;
      }
      int hi = percent + 2 < value.length() ? Character.digit(value.charAt(percent + 1), 16) : -1;
      int lo = percent + 2 < value.length() ? Character.digit(value.charAt(percent + 2), 16) : -1;
      if (hi < 0 || lo < 0) {
        throw new IllegalArgumentException("bad percent encoding");
      }
      bytes.write((hi << 4) | lo);
      i = percent + 3;
    }
    return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
  }

  static final class Hop {
    final String user;
    final String host;
    final int port;

    Hop(String user, String host, int port) {
      this.user = user;
      this.host = host;
      this.port = port;
    }
  }

  /** Tunnels one session through a direct-tcpip channel of a hop, which it never disconnects. */
  private static final class ChannelProxy implements ReadTimeoutProxy {
    private final Session hop;
    private ChannelDirectTCPIP channel;
    private volatile TunnelBuffer in;
    private OutputStream out;

    ChannelProxy(Session hop) {
      this.hop = hop;
    }

    @Override
    public void connect(SocketFactory socketFactory, String host, int port, int timeout)
        throws JSchException {
      if (!hop.isConnected()) {
        throw new JSchException("ProxyJump hop " + hop.getHost() + " is not connected");
      }
      try {
        ChannelDirectTCPIP opened = (ChannelDirectTCPIP) hop.openChannel("direct-tcpip");
        if (opened == null) {
          throw new JSchException("ProxyJump hop " + hop.getHost() + " is closing");
        }
        channel = opened;
        opened.setLocalWindowSizeMax(CHANNEL_WINDOW_SIZE);
        opened.setLocalWindowSize(CHANNEL_WINDOW_SIZE);
        opened.setLocalPacketSize(CHANNEL_PACKET_SIZE);
        opened.setHost(host);
        opened.setPort(port);
        TunnelBuffer buffer = new TunnelBuffer(INITIAL_BUFFER_SIZE, CHANNEL_WINDOW_SIZE);
        // The channel writes received data to the sink and closes it on EOF or disconnect.
        opened.setOutputStream(buffer.sink());
        in = buffer;
        out = opened.getOutputStream();
        opened.connect(timeout);
        if (!opened.isConnected()) {
          throw new JSchException("Unable to connect ProxyJump channel to " + host);
        }
        // Bound each read of the handshake like a socket's connect timeout would.
        buffer.setTimeout(timeout);
      } catch (IOException e) {
        close();
        throw new JSchException(e.toString(), e);
      } catch (JSchException | RuntimeException e) {
        close();
        throw e;
      }
    }

    @Override
    public InputStream getInputStream() {
      return in;
    }

    @Override
    public OutputStream getOutputStream() {
      return out;
    }

    @Override
    public Socket getSocket() {
      return null;
    }

    @Override
    public void setReadTimeout(int timeout) throws JSchException {
      if (timeout < 0) {
        throw new JSchException("invalid timeout value");
      }
      if (in != null) {
        in.setTimeout(timeout);
      }
    }

    @Override
    public void close() {
      if (channel != null) {
        channel.disconnect();
        channel = null;
      }
      if (in != null) {
        in.close();
        in = null;
      }
      out = null;
    }
  }

  /**
   * Bounded byte queue from a hop channel to the session tunnelled through it. The channel writes
   * received data on the hop session's reader thread; the tunnelled session reads it on its own.
   * Unlike {@link java.io.PipedInputStream} it does not care which threads use it, wakes a waiting
   * side at once, and can bound a read by a timeout. It grows up to a limit before blocking the
   * writer, which is how a slow reader throttles the hop.
   */
  static final class TunnelBuffer extends InputStream {
    private final int limit;
    private byte[] ring;
    private int head; // index of the next byte to read
    private int count; // bytes waiting to be read
    private boolean closed; // no more data will flow, in either direction
    private volatile int timeout;
    private final OutputStream sink = new Sink();

    TunnelBuffer(int initialSize, int limit) {
      if (initialSize <= 0) {
        throw new IllegalArgumentException("buffer size must be positive");
      }
      this.ring = new byte[initialSize];
      this.limit = Math.max(initialSize, limit);
    }

    /** The stream the channel writes received data to. */
    OutputStream sink() {
      return sink;
    }

    void setTimeout(int timeout) {
      this.timeout = timeout;
    }

    @Override
    public synchronized int available() {
      return count;
    }

    @Override
    public int read() throws IOException {
      byte[] single = new byte[1];
      return read(single, 0, 1) < 0 ? -1 : single[0] & 0xff;
    }

    @Override
    public synchronized int read(byte[] bytes, int offset, int length) throws IOException {
      if (offset < 0 || length < 0 || offset > bytes.length - length) {
        throw new IndexOutOfBoundsException();
      }
      if (length == 0) {
        return 0;
      }
      int readTimeout = timeout;
      long deadline =
          readTimeout > 0 ? System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(readTimeout) : 0;
      while (count == 0) {
        if (closed) {
          return -1;
        }
        long left = 0;
        if (deadline != 0) {
          long leftNanos = deadline - System.nanoTime();
          if (leftNanos <= 0) {
            throw new SocketTimeoutException("ProxyJump read timed out");
          }
          left = Math.max(1, TimeUnit.NANOSECONDS.toMillis(leftNanos));
        }
        try {
          wait(left);
        } catch (InterruptedException e) {
          throw interrupted(e);
        }
      }
      int n = Math.min(length, count);
      int first = Math.min(n, ring.length - head);
      System.arraycopy(ring, head, bytes, offset, first);
      System.arraycopy(ring, 0, bytes, offset + first, n - first);
      head = (head + n) % ring.length;
      count -= n;
      notifyAll();
      return n;
    }

    /** Ends the stream: a reader drains what is buffered and then sees EOF, a writer fails. */
    @Override
    public synchronized void close() {
      closed = true;
      notifyAll();
    }

    private static InterruptedIOException interrupted(InterruptedException cause) {
      Thread.currentThread().interrupt();
      InterruptedIOException interrupted =
          new InterruptedIOException("ProxyJump tunnel interrupted");
      interrupted.initCause(cause);
      return interrupted;
    }

    /** The channel's side: blocks while the buffer is full, fails once it is closed. */
    private final class Sink extends OutputStream {
      @Override
      public void write(int b) throws IOException {
        write(new byte[] {(byte) b}, 0, 1);
      }

      @Override
      public void write(byte[] bytes, int offset, int length) throws IOException {
        synchronized (TunnelBuffer.this) {
          while (length > 0) {
            while (!closed && count == ring.length && !grow()) {
              try {
                TunnelBuffer.this.wait();
              } catch (InterruptedException e) {
                throw interrupted(e);
              }
            }
            if (closed) {
              throw new IOException("ProxyJump tunnel closed");
            }
            int n = Math.min(length, ring.length - count);
            int tail = (head + count) % ring.length;
            int first = Math.min(n, ring.length - tail);
            System.arraycopy(bytes, offset, ring, tail, first);
            System.arraycopy(bytes, offset + first, ring, 0, n - first);
            count += n;
            offset += n;
            length -= n;
            TunnelBuffer.this.notifyAll();
          }
        }
      }

      @Override
      public void close() {
        TunnelBuffer.this.close();
      }

      private boolean grow() {
        if (ring.length >= limit) {
          return false;
        }
        byte[] bigger = new byte[(int) Math.min(2L * ring.length, limit)];
        int first = Math.min(count, ring.length - head);
        System.arraycopy(ring, head, bigger, 0, first);
        System.arraycopy(ring, 0, bigger, first, count - first);
        ring = bigger;
        head = 0;
        return true;
      }
    }
  }
}
