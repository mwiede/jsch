/*
 * Copyright (c) 2013-2018 ymnk, JCraft,Inc. All rights reserved.
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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This class implements ConfigRepository interface, and parses OpenSSH's configuration file. The
 * following keywords will be recognized,
 *
 * <ul>
 * <li>Host</li>
 * <li>Match (all, canonical, final, host, originalhost, user, localuser, tagged, version,
 * localnetwork; exec, command and sessiontype are rejected)</li>
 * <li>Tag</li>
 * <li>User</li>
 * <li>Hostname</li>
 * <li>Port</li>
 * <li>Include</li>
 * <li>PreferredAuthentications</li>
 * <li>PubkeyAcceptedAlgorithms</li>
 * <li>FingerprintHash</li>
 * <li>IdentityFile</li>
 * <li>NumberOfPasswordPrompts</li>
 * <li>ConnectTimeout</li>
 * <li>HostKeyAlias</li>
 * <li>UserKnownHostsFile</li>
 * <li>KexAlgorithms</li>
 * <li>HostKeyAlgorithms</li>
 * <li>Ciphers</li>
 * <li>Macs</li>
 * <li>Compression</li>
 * <li>CompressionLevel</li>
 * <li>ForwardAgent</li>
 * <li>RequestTTY</li>
 * <li>ServerAliveInterval</li>
 * <li>LocalForward</li>
 * <li>RemoteForward</li>
 * <li>ClearAllForwardings</li>
 * <li>CASignatureAlgorithms</li>
 * </ul>
 *
 * <p>
 * Like OpenSSH, relative {@code Include} paths are resolved against {@code ~/.ssh}, or against the
 * file's directory for {@link #parseSystemFile(String)}, and include nesting is limited to 16
 * levels. {@code Match final} and {@code Match canonical} (with {@code CanonicalizeHostname}) cause
 * a second pass in which patterns see the resolved host name; settings from the first pass still
 * win. JSch does not canonicalize host names. {@code Match exec}, {@code command} and
 * {@code sessiontype} are rejected, because JSch never runs commands from the config and does not
 * know the session type when it reads it.
 *
 * <p>
 * For {@code IdentityFile} and {@code UserKnownHostsFile}, a leading {@code ~} and the tokens
 * {@code %%, %C, %d, %h, %i, %j, %k, %L, %l, %n, %p, %r, %u} and {@code ${ENV}} are expanded;
 * {@code HostName} expands {@code %h} and {@code %%}. An unknown token or an undefined environment
 * variable fails the session rather than using a literal path.
 *
 * @see ConfigRepository
 */
public class OpenSSHConfig implements ConfigRepository {

  private static final Set<String> keysWithListAdoption = Stream
      .of("KexAlgorithms", "Ciphers", "HostKeyAlgorithms", "MACs", "PubkeyAcceptedAlgorithms",
          "PubkeyAcceptedKeyTypes", "CASignatureAlgorithms")
      .map(string -> string.toUpperCase(Locale.ROOT)).collect(Collectors.toSet());

  /**
   * Parses the given string, and returns an instance of ConfigRepository.
   *
   * Include directives in {@code conf} may read additional files. Only parse trusted config text.
   * JSch does not impose OpenSSH's file owner/mode checks because embedded applications may use
   * application-managed files or filesystems without POSIX permissions; callers must enforce their
   * own trust policy.
   *
   * @param conf string, which includes OpenSSH's config
   * @return an instanceof OpenSSHConfig
   */
  public static OpenSSHConfig parse(String conf) throws IOException {
    try (Reader r = new StringReader(conf)) {
      try (BufferedReader br = new BufferedReader(r)) {
        return new OpenSSHConfig(br, "ssh config", userSshDirectory(), new HashSet<>());
      }
    }
  }

  /**
   * Parses the given file, and returns an instance of ConfigRepository. Included files are read
   * without owner/mode checks; callers choose which config files are trusted, including on
   * platforms without POSIX ownership metadata.
   *
   * @param file OpenSSH's config file
   * @return an instanceof OpenSSHConfig
   */
  public static OpenSSHConfig parseFile(String file) throws IOException {
    return parseFile(file, userSshDirectory());
  }

  static OpenSSHConfig parseFile(String file, Path includeBase) throws IOException {
    Path path = Paths.get(Util.checkTilde(file));
    try (BufferedReader br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      Set<Path> activeFiles = new HashSet<>();
      activeFiles.add(path.toRealPath());
      return new OpenSSHConfig(br, file, includeBase, activeFiles);
    }
  }

  /**
   * Parses a system-wide config file such as {@code /etc/ssh/ssh_config}. Unlike
   * {@link #parseFile(String)}, relative Include paths are resolved against the directory of
   * {@code file} rather than {@code ~/.ssh}, as OpenSSH does for its system config.
   *
   * @param file system-wide OpenSSH config file
   * @return an instanceof OpenSSHConfig
   */
  public static OpenSSHConfig parseSystemFile(String file) throws IOException {
    Path parent = Paths.get(Util.checkTilde(file)).toAbsolutePath().getParent();
    return parseFile(file, parent != null ? parent : userSshDirectory());
  }

  private static Path userSshDirectory() {
    return Paths.get(Util.getSystemProperty("user.home"), ".ssh");
  }

  private OpenSSHConfig(BufferedReader br, String source, Path includeBase, Set<Path> activeFiles)
      throws IOException {
    Section global = new Section("", null, Collections.emptyList(), Collections.emptyList());
    sections.add(global);
    try {
      parse(br, new Frame(source, includeBase, activeFiles, 0), global, Collections.emptyList(),
          Collections.emptyList());
    } catch (IOException e) {
      // The message names the file and line, so an application that only logs still shows why.
      if (JSch.getLogger().isEnabled(Logger.ERROR)) {
        JSch.getLogger().log(Logger.ERROR, "Cannot use OpenSSH config: " + e.getMessage());
      }
      throw e;
    }
  }

  private static final class Section {
    final String host;
    final MatchExpression match;
    final List<String> enclosingHosts;
    final List<MatchExpression> enclosingMatches;
    final Vector<String[]> options = new Vector<>();

    Section(String host, MatchExpression match, List<String> enclosingHosts,
        List<MatchExpression> enclosingMatches) {
      this.host = host;
      this.match = match;
      this.enclosingHosts = enclosingHosts;
      this.enclosingMatches = enclosingMatches;
    }
  }

  private static final int MAX_INCLUDE_DEPTH = 16; // as OpenSSH's READCONF_MAX_DEPTH

  private final Vector<Section> sections = new Vector<>();
  // OpenSSH re-reads the config once more when it has a non-negated "Match final".
  private boolean wantFinalPass;

  /** One file being parsed: where it came from, and what its Include lines are allowed to do. */
  private static final class Frame {
    final String source;
    final Path includeBase;
    final Set<Path> activeFiles;
    final int depth;

    Frame(String source, Path includeBase, Set<Path> activeFiles, int depth) {
      this.source = source;
      this.includeBase = includeBase;
      this.activeFiles = activeFiles;
      this.depth = depth;
    }

    Frame include(Path path) {
      return new Frame(path.toString(), includeBase, activeFiles, depth + 1);
    }
  }

  private void parse(BufferedReader br, Frame frame, Section current, List<String> enclosingHosts,
      List<MatchExpression> enclosingMatches) throws IOException {
    String line;
    int lineNumber = 0;
    while ((line = br.readLine()) != null) {
      lineNumber++;
      try {
        current = parseLine(line, frame, current, enclosingHosts, enclosingMatches);
      } catch (IOException e) {
        throw new IOException(frame.source + ":" + lineNumber + ": " + e.getMessage(), e);
      }
    }
  }

  private Section parseLine(String line, Frame frame, Section current, List<String> enclosingHosts,
      List<MatchExpression> enclosingMatches) throws IOException {
    line = line.trim();
    if (line.isEmpty() || line.startsWith("#")) {
      return current;
    }
    String[] keyValue = line.split("[= \t]", 2);
    if (keyValue.length < 2) {
      if (line.equalsIgnoreCase("Host") || line.equalsIgnoreCase("Match")
          || line.equalsIgnoreCase("Include")) {
        throw new IOException(line + " requires an argument");
      }
      return current;
    }
    String key = keyValue[0].trim();
    String value = keyValue[1].trim();
    if (value.startsWith("=")) {
      value = value.substring(1).trim();
    }
    value = stripComment(value);
    if (key.equalsIgnoreCase("Host")) {
      if (value.isEmpty()) {
        throw new IOException("Host requires at least one pattern");
      }
      Section next = new Section(value, null, enclosingHosts, enclosingMatches);
      sections.add(next);
      return next;
    }
    if (key.equalsIgnoreCase("Match")) {
      MatchExpression match = parseMatch(value);
      wantFinalPass |= match.requestsFinalPass;
      Section next = new Section("", match, enclosingHosts, enclosingMatches);
      sections.add(next);
      return next;
    }
    if (value.isEmpty() && !key.equalsIgnoreCase("Include")) {
      return current;
    }
    if (key.equalsIgnoreCase("Include")) {
      includeFiles(value, frame, current);
      Section next = new Section(current.host, current.match, enclosingHosts, enclosingMatches);
      sections.add(next);
      return next;
    }
    current.options.addElement(new String[] {key, value});
    return current;
  }

  /** Drops a comment: an unquoted '#' starting a word, as in OpenSSH's argv_split(). */
  private static String stripComment(String value) {
    char quote = 0;
    int i = 0;
    while (i < value.length()) {
      char ch = value.charAt(i);
      int step = 1;
      if (ch == '\\' && i + 1 < value.length() && isEscapable(value.charAt(i + 1), quote)) {
        step = 2;
      } else if (quote != 0) {
        if (ch == quote) {
          quote = 0;
        }
      } else if (ch == '"' || ch == '\'') {
        quote = ch;
      } else if (ch == '#' && (i == 0 || Character.isWhitespace(value.charAt(i - 1)))) {
        return value.substring(0, i).trim();
      }
      i += step;
    }
    return value;
  }

  private static boolean isEscapable(char next, char quote) {
    return next == '\\' || next == '"' || next == '\'' || (quote == 0 && next == ' ');
  }

  private void includeFiles(String value, Frame frame, Section current) throws IOException {
    List<String> enclosingHosts = new ArrayList<>(current.enclosingHosts);
    List<MatchExpression> enclosingMatches = new ArrayList<>(current.enclosingMatches);
    if (!current.host.isEmpty()) {
      enclosingHosts.add(current.host);
    }
    if (current.match != null) {
      enclosingMatches.add(current.match);
    }
    for (String pattern : includeArguments(value)) {
      for (Path path : expandInclude(pattern, frame.includeBase)) {
        includeFile(path, frame, enclosingHosts, enclosingMatches);
      }
    }
  }

  private void includeFile(Path path, Frame frame, List<String> enclosingHosts,
      List<MatchExpression> enclosingMatches) throws IOException {
    if (frame.depth >= MAX_INCLUDE_DEPTH) {
      throw new IOException("Too many recursive configuration includes: " + path);
    }
    Path realPath = path.toRealPath();
    if (!frame.activeFiles.add(realPath)) {
      throw new IOException("Recursive configuration include: " + path);
    }
    try (BufferedReader included = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      Section includedContext = new Section("", null, enclosingHosts, enclosingMatches);
      sections.add(includedContext);
      parse(included, frame.include(path), includedContext, enclosingHosts, enclosingMatches);
    } finally {
      frame.activeFiles.remove(realPath);
    }
  }

  private static List<String> includeArguments(String value) throws IOException {
    return arguments(value, "Include requires at least one path");
  }

  private static List<String> arguments(String value, String missing) throws IOException {
    ArgumentParser parser = new ArgumentParser();
    for (int i = 0; i < value.length(); i++) {
      if (!parser.accept(value.charAt(i), i + 1 < value.length() ? value.charAt(i + 1) : 0)) {
        break;
      }
    }
    return parser.finish(value, missing);
  }

  private static MatchExpression parseMatch(String value) throws IOException {
    if (value.isEmpty()) {
      throw new IOException("Match requires at least one criterion");
    }
    List<String> arguments = arguments(value, "Match requires at least one criterion");
    List<MatchCriterion> criteria = new ArrayList<>();
    int next = 0;
    while (next < arguments.size()) {
      next = addCriterion(arguments, next, criteria);
    }
    return new MatchExpression(criteria);
  }

  /** Parses the criterion at {@code index}, appends it, and returns the index after its words. */
  private static int addCriterion(List<String> arguments, int index, List<MatchCriterion> criteria)
      throws IOException {
    String attribute = arguments.get(index);
    int next = index + 1;
    boolean negated = attribute.startsWith("!");
    if (negated) {
      attribute = attribute.substring(1);
    }
    int equals = attribute.indexOf('=');
    String type =
        (equals < 0 ? attribute : attribute.substring(0, equals)).toLowerCase(Locale.ROOT);
    String pattern = equals < 0 ? null : attribute.substring(equals + 1);
    if (MatchCriterion.WITHOUT_ARGUMENT.contains(type)) {
      if (type.equals("all") && (next != arguments.size() || !onlyPassCriteria(criteria))) {
        throw new IOException("Match all cannot be combined with other criteria");
      }
      criteria.add(new MatchCriterion(type, null, negated));
      return next;
    }
    rejectUnsupported(type);
    if (pattern == null && next < arguments.size()) {
      pattern = arguments.get(next++);
    }
    if (pattern == null || (pattern.isEmpty() && !type.equals("tagged"))) {
      throw new IOException("Missing Match pattern for " + type);
    }
    criteria.add(new MatchCriterion(type, pattern, negated));
    return next;
  }

  private static void rejectUnsupported(String type) throws IOException {
    if (MatchCriterion.UNSUPPORTED.contains(type)) {
      throw new IOException("Unsupported Match criterion: " + type
          + (type.equals("exec") ? " (JSch never runs commands from ssh config)"
              : " (not known when JSch reads the config)"));
    }
    if (!MatchCriterion.WITH_ARGUMENT.contains(type)) {
      throw new IOException("Unsupported Match criterion: " + type);
    }
  }

  private static boolean onlyPassCriteria(List<MatchCriterion> criteria) {
    for (MatchCriterion criterion : criteria) {
      if (!criterion.type.equals("canonical") && !criterion.type.equals("final")) {
        return false;
      }
    }
    return true;
  }

  /** What a Match line is evaluated against during one pass over the config. */
  private static final class MatchContext {
    final String originalHost;
    final boolean finalPass;
    String effectiveHost;
    String remoteUser;
    String tag;

    MatchContext(String originalHost, boolean finalPass) {
      this.originalHost = originalHost;
      this.finalPass = finalPass;
    }
  }

  private static final class MatchCriterion {
    static final Set<String> WITHOUT_ARGUMENT =
        new HashSet<>(Arrays.asList("all", "canonical", "final"));
    static final Set<String> WITH_ARGUMENT = new HashSet<>(Arrays.asList("host", "originalhost",
        "user", "localuser", "tagged", "version", "localnetwork"));
    static final Set<String> UNSUPPORTED =
        new HashSet<>(Arrays.asList("exec", "command", "sessiontype"));

    final String type;
    final String pattern;
    final boolean negated;
    final List<LocalNetwork> networks;

    MatchCriterion(String type, String pattern, boolean negated) throws IOException {
      this.type = type;
      this.pattern = pattern;
      this.negated = negated;
      this.networks =
          type.equals("localnetwork") ? LocalNetwork.parseList(pattern) : Collections.emptyList();
    }

    boolean matches(MatchContext context) {
      return matchesUnnegated(context) != negated;
    }

    private boolean matchesUnnegated(MatchContext context) {
      switch (type) {
        case "all":
          return true;
        case "canonical":
        case "final":
          // JSch does not canonicalize, so both hold exactly in the final pass.
          return context.finalPass;
        case "localnetwork":
          return LocalNetwork.matchesInterface(networks);
        default:
          String candidate = candidate(context);
          if (candidate == null) {
            return false;
          }
          // An empty pattern (Match tagged "") matches only an empty value, as in OpenSSH.
          return pattern.isEmpty() ? candidate.isEmpty()
              : matchesPatternList(pattern, Util.str2byte(candidate), ",");
      }
    }

    private String candidate(MatchContext context) {
      switch (type) {
        case "host":
          return context.effectiveHost;
        case "originalhost":
          return context.originalHost;
        case "user":
          return context.remoteUser;
        case "localuser":
          return Util.getSystemProperty("user.name");
        case "tagged":
          return context.tag == null ? "" : context.tag;
        case "version":
          return "JSCH_" + JSch.VERSION;
        default:
          return null;
      }
    }
  }

  private static final class MatchExpression {
    final List<MatchCriterion> criteria;
    final boolean requestsFinalPass;

    MatchExpression(List<MatchCriterion> criteria) {
      this.criteria = criteria;
      boolean finalPass = false;
      for (MatchCriterion criterion : criteria) {
        finalPass |= criterion.type.equals("final") && !criterion.negated;
      }
      this.requestsFinalPass = finalPass;
    }

    boolean matches(MatchContext context) {
      for (MatchCriterion criterion : criteria) {
        if (!criterion.matches(context)) {
          return false;
        }
      }
      return true;
    }
  }

  /** A CIDR entry of {@code Match localnetwork}, compared with local interface addresses. */
  static final class LocalNetwork {
    private final byte[] network;
    private final int bits;

    private LocalNetwork(byte[] network, int bits) {
      this.network = network;
      this.bits = bits;
    }

    static List<LocalNetwork> parseList(String list) throws IOException {
      List<LocalNetwork> networks = new ArrayList<>();
      for (String entry : list.split(",", -1)) {
        networks.add(parse(entry.trim(), list));
      }
      return networks;
    }

    private static LocalNetwork parse(String entry, String list) throws IOException {
      int slash = entry.indexOf('/');
      String address = slash < 0 ? entry : entry.substring(0, slash);
      byte[] bytes = parseLiteral(address);
      if (bytes.length == 0) {
        throw new IOException("Invalid Match localnetwork address list: " + list);
      }
      int bits = bytes.length * 8;
      if (slash >= 0) {
        String length = entry.substring(slash + 1);
        // Digits only: Integer.parseInt would also accept a sign.
        // Digits only, as OpenSSH: a sign is rejected, zero padding and overflow handled below.
        try {
          bits = length.matches("\\d+") ? Integer.parseInt(length) : -1;
        } catch (NumberFormatException e) {
          bits = -1;
        }
      }
      if (bits < 0 || bits > bytes.length * 8 || !hostBitsZero(bytes, bits)) {
        throw new IOException("Invalid Match localnetwork address list: " + list);
      }
      return new LocalNetwork(bytes, bits);
    }

    /** Parses an IP literal without ever resolving a host name. */
    private static byte[] parseLiteral(String address) {
      // Decimal octets 0-255 without leading zeros, as inet_pton reads them; 010 is not accepted.
      String octet = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
      boolean ipv4 = address.matches(octet + "(\\." + octet + "){3}");
      boolean ipv6 = address.indexOf(':') >= 0 && address.matches("[0-9A-Fa-f:.]+");
      if (!ipv4 && !ipv6) {
        return new byte[0];
      }
      try {
        return InetAddress.getByName(address).getAddress();
      } catch (UnknownHostException e) {
        return new byte[0];
      }
    }

    private static boolean hostBitsZero(byte[] address, int bits) {
      for (int i = 0; i < address.length * 8; i++) {
        if (i >= bits && ((address[i / 8] & 0xff) & (0x80 >>> (i % 8))) != 0) {
          return false;
        }
      }
      return true;
    }

    boolean contains(byte[] address) {
      if (address.length != network.length) {
        return false;
      }
      for (int i = 0; i < bits; i++) {
        int mask = 0x80 >>> (i % 8);
        if (((address[i / 8] & 0xff) & mask) != ((network[i / 8] & 0xff) & mask)) {
          return false;
        }
      }
      return true;
    }

    static boolean matchesInterface(List<LocalNetwork> networks) {
      try {
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces != null && interfaces.hasMoreElements()) {
          for (InterfaceAddress address : interfaces.nextElement().getInterfaceAddresses()) {
            for (LocalNetwork network : networks) {
              if (network.contains(address.getAddress().getAddress())) {
                return true;
              }
            }
          }
        }
      } catch (SocketException e) {
        // No readable interfaces: nothing matches.
      }
      return false;
    }
  }

  private static final class ArgumentParser {
    private final List<String> arguments = new ArrayList<>();
    private final StringBuilder argument = new StringBuilder();
    private char quote;
    private boolean escaped;
    private boolean quoted;

    boolean accept(char ch, char next) {
      if (escaped) {
        argument.append(ch);
        escaped = false;
      } else if (ch == '\\') {
        if (isEscapable(next, quote)) {
          escaped = true;
        } else {
          argument.append(ch);
        }
      } else if (quote != 0) {
        if (ch == quote) {
          quote = 0;
        } else {
          argument.append(ch);
        }
      } else if (ch == '"' || ch == '\'') {
        quote = ch;
        quoted = true;
      } else if (Character.isWhitespace(ch)) {
        flush();
      } else if (ch == '#' && argument.length() == 0 && !quoted) {
        return false;
      } else {
        argument.append(ch);
      }
      return true;
    }

    List<String> finish(String value, String missing) throws IOException {
      if (quote != 0) {
        throw new IOException("Unterminated quoted argument: " + value);
      }
      flush();
      if (arguments.isEmpty()) {
        throw new IOException(missing);
      }
      return arguments;
    }

    private void flush() {
      // An empty quoted argument such as "" is kept: Match tagged "" is meaningful.
      if (argument.length() > 0 || quoted) {
        arguments.add(argument.toString());
        argument.setLength(0);
      }
      quoted = false;
    }
  }

  private static List<Path> expandInclude(String pattern, Path includeBase) throws IOException {
    String name;
    try {
      name = ConfigTokenExpander.expandPath(pattern,
          token -> token == 'd' ? Util.getSystemProperty("user.home") : null);
    } catch (JSchException e) {
      throw new IOException("Invalid Include path: " + pattern, e);
    }
    if (name.startsWith("~")) {
      throw new IOException(
          "Unsupported Include home path (only the current user's home is known): " + pattern);
    }
    try {
      return matchIncludeFiles(name, includeBase);
    } catch (InvalidPathException e) {
      throw new IOException("Invalid Include path: " + pattern, e);
    }
  }

  private static List<Path> matchIncludeFiles(String pattern, Path includeBase) throws IOException {
    int wildcard = firstWildcard(pattern);
    if (wildcard < 0) {
      Path path = resolve(Paths.get(pattern), includeBase);
      return Files.isRegularFile(path) ? Collections.singletonList(path) : Collections.emptyList();
    }
    int separator = lastSeparatorBefore(pattern, wildcard);
    Path prefix = separator < 0 ? includeBase
        : resolve(Paths.get(pattern.substring(0, separator + 1)), includeBase);
    List<Path> candidates = Collections.singletonList(prefix);
    for (String segment : splitSegments(pattern.substring(separator + 1))) {
      candidates = firstWildcard(segment) < 0 ? literalSegment(candidates, segment)
          : globSegment(candidates, segment, prefix, pattern);
      if (candidates.isEmpty()) {
        break;
      }
    }
    return candidates.stream().filter(Files::isRegularFile)
        .sorted(Comparator.comparing(Path::toString)).collect(Collectors.toList());
  }

  private static Path resolve(Path path, Path includeBase) {
    return path.isAbsolute() ? path : includeBase.resolve(path);
  }

  private static List<Path> literalSegment(List<Path> directories, String segment) {
    List<Path> next = new ArrayList<>();
    for (Path directory : directories) {
      Path path = directory.resolve(segment);
      if (Files.exists(path)) {
        next.add(path);
      }
    }
    return next;
  }

  private static List<Path> globSegment(List<Path> directories, String segment, Path prefix,
      String pattern) throws IOException {
    PathMatcher matcher;
    try {
      matcher = prefix.getFileSystem()
          .getPathMatcher("glob:" + segment.replace("{", "\\{").replace("}", "\\}"));
    } catch (IllegalArgumentException e) {
      throw new IOException("Invalid Include pattern: " + pattern, e);
    }
    boolean includeHidden = segment.startsWith(".");
    List<Path> next = new ArrayList<>();
    for (Path directory : directories) {
      if (!Files.isDirectory(directory)) {
        continue;
      }
      try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
        for (Path entry : entries) {
          Path filename = entry.getFileName();
          if ((includeHidden || !filename.toString().startsWith("."))
              && matcher.matches(filename)) {
            next.add(entry);
          }
        }
      } catch (IOException | DirectoryIteratorException e) {
        // Like OpenSSH's glob(), an unreadable directory contributes no matches.
      }
    }
    return next;
  }

  private static int firstWildcard(String value) {
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch == '*' || ch == '?' || ch == '[') {
        return i;
      }
    }
    return -1;
  }

  private static int lastSeparatorBefore(String value, int limit) {
    for (int i = limit - 1; i >= 0; i--) {
      char ch = value.charAt(i);
      if (ch == '/' || (File.separatorChar == '\\' && ch == '\\')) {
        return i;
      }
    }
    return -1;
  }

  private static List<String> splitSegments(String pattern) {
    List<String> segments = new ArrayList<>();
    int start = 0;
    for (int i = 0; i <= pattern.length(); i++) {
      if (i == pattern.length() || pattern.charAt(i) == '/'
          || (File.separatorChar == '\\' && pattern.charAt(i) == '\\')) {
        if (i > start) {
          segments.add(pattern.substring(start, i));
        }
        start = i + 1;
      }
    }
    return segments;
  }

  private static boolean matchesHostPatterns(String patternList, byte[] host) {
    return matchesPatternList(patternList, host, "[ \\t]");
  }

  private static boolean matchesPatternList(String patternList, byte[] host, String separator) {
    boolean positive = false;
    for (String pattern : patternList.split(separator)) {
      boolean negate = pattern.startsWith("!");
      String candidate = negate ? pattern.substring(1) : pattern;
      if (Util.glob(Util.str2byte(candidate.trim()), host)) {
        if (negate) {
          return false;
        }
        positive = true;
      }
    }
    return positive;
  }

  @Override
  public Config getConfig(String host) {
    return new MyConfig(host, null);
  }

  @Override
  public Config getConfig(String host, String user) {
    return new MyConfig(host, user);
  }

  /**
   * Returns mapping of jsch config property names to OpenSSH property names.
   *
   * @return map
   */
  static Hashtable<String, String> getKeymap() {
    return keymap;
  }

  private static final Hashtable<String, String> keymap = new Hashtable<>();

  static {
    keymap.put("kex", "KexAlgorithms");
    keymap.put("server_host_key", "HostKeyAlgorithms");
    keymap.put("cipher.c2s", "Ciphers");
    keymap.put("cipher.s2c", "Ciphers");
    keymap.put("mac.c2s", "Macs");
    keymap.put("mac.s2c", "Macs");
    keymap.put("compression.s2c", "Compression");
    keymap.put("compression.c2s", "Compression");
    keymap.put("compression_level", "CompressionLevel");
    keymap.put("MaxAuthTries", "NumberOfPasswordPrompts");
    keymap.put("ca_signature_algorithms", "CASignatureAlgorithms");
  }

  class MyConfig implements Config {

    private String host;
    private Vector<Vector<String[]>> _configs = new Vector<>();

    MyConfig(String host, String user) {
      this.host = host;
      MatchContext first = new MatchContext(host, false);
      first.effectiveHost = host;
      first.remoteUser = user != null ? user : Util.getSystemProperty("user.name");
      Set<String> obtained = new HashSet<>();
      if (user != null) {
        obtained.add("USER");
      }
      Set<Vector<String[]>> applied = Collections.newSetFromMap(new IdentityHashMap<>());
      evaluate(host, first, obtained, applied);
      String canonicalize = find("CanonicalizeHostname");
      if (wantFinalPass || "yes".equalsIgnoreCase(canonicalize)
          || "always".equalsIgnoreCase(canonicalize)) {
        // Like OpenSSH's final pass: patterns now see the resolved host name, and settings
        // obtained in the first pass still win.
        MatchContext last = new MatchContext(host, true);
        last.effectiveHost = first.effectiveHost;
        last.remoteUser = first.remoteUser;
        last.tag = first.tag;
        obtained.add("HOSTNAME");
        evaluate(first.effectiveHost, last, obtained, applied);
      }
    }

    private void evaluate(String patternHost, MatchContext context, Set<String> obtained,
        Set<Vector<String[]>> applied) {
      byte[] hostBytes = Util.str2byte(patternHost);
      Map<MatchExpression, Boolean> matchResults = new IdentityHashMap<>();
      for (Section section : sections) {
        if (applied.contains(section.options)
            || !sectionMatches(section, hostBytes, context, matchResults)) {
          continue;
        }
        applied.add(section.options);
        _configs.addElement(section.options);
        for (String[] option : section.options) {
          remember(option, context, obtained);
        }
      }
    }

    private boolean sectionMatches(Section section, byte[] hostBytes, MatchContext context,
        Map<MatchExpression, Boolean> matchResults) {
      boolean matches = section.host.isEmpty() || matchesHostPatterns(section.host, hostBytes);
      for (String enclosingHost : section.enclosingHosts) {
        matches &= matchesHostPatterns(enclosingHost, hostBytes);
      }
      // Every Match line is still evaluated once, so later settings cannot change its result.
      if (section.match != null) {
        matches &= matchOnce(section.match, context, matchResults);
      }
      for (MatchExpression enclosingMatch : section.enclosingMatches) {
        matches &= matchOnce(enclosingMatch, context, matchResults);
      }
      return matches;
    }

    /** Tracks the first HostName, User and Tag, which later Match lines evaluate. */
    private void remember(String[] option, MatchContext context, Set<String> obtained) {
      String key = option[0].toUpperCase(Locale.ROOT);
      if (!obtained.add(key)) {
        return;
      }
      if (key.equals("HOSTNAME")) {
        // Session rejects unsupported HostName tokens; Match must see the supported forms alike.
        context.effectiveHost = ConfigTokenExpander.expandKnownTokens(option[1],
            token -> token == 'h' ? context.originalHost : null);
      } else if (key.equals("USER")) {
        context.remoteUser = option[1];
      } else if (key.equals("TAG")) {
        context.tag = option[1];
      }
    }

    private boolean matchOnce(MatchExpression expression, MatchContext context,
        Map<MatchExpression, Boolean> results) {
      Boolean result = results.get(expression);
      if (result == null) {
        result = expression.matches(context);
        results.put(expression, result);
      }
      return result;
    }

    private String find(String key) {
      String originalKey = key;
      if (keymap.get(key) != null) {
        key = keymap.get(key);
      }
      key = key.toUpperCase(Locale.ROOT);
      String value = null;
      for (int i = 0; i < _configs.size(); i++) {
        Vector<String[]> v = _configs.elementAt(i);
        for (int j = 0; j < v.size(); j++) {
          String[] kv = v.elementAt(j);
          if (kv[0].toUpperCase(Locale.ROOT).equals(key)) {
            value = kv[1];
            break;
          }
        }
        if (value != null)
          break;
      }

      if (value != null && (key.equals("SERVERALIVEINTERVAL") || key.equals("CONNECTTIMEOUT"))) {
        try {
          int timeout = Integer.parseInt(value);
          value = Integer.toString(timeout * 1000);
        } catch (NumberFormatException e) {
          logError(originalKey, e);
        }
      }

      if (keysWithListAdoption.contains(key) && value != null
          && (value.startsWith("+") || value.startsWith("-") || value.startsWith("^"))) {

        String origConfig = JSch.getConfig(originalKey).trim();

        if (value.startsWith("+")) {
          value = origConfig + "," + value.substring(1).trim();
        } else if (value.startsWith("-")) {
          List<String> algList =
              Arrays.stream(Util.split(origConfig, ",")).collect(Collectors.toList());
          for (String alg : Util.split(value.substring(1).trim(), ",")) {
            algList.remove(alg.trim());
          }
          value = String.join(",", algList);
        } else if (value.startsWith("^")) {
          value = value.substring(1).trim() + "," + origConfig;
        }
      }

      return value;
    }

    private void logError(String originalKey, NumberFormatException e) {
      Logger logger = JSch.getLogger();
      if (logger != null) {
        logger.log(Logger.ERROR, "Error during parsing of " + originalKey + ": " + e.getMessage(),
            e);
      }
    }

    private String[] multiFind(String key) {
      key = key.toUpperCase(Locale.ROOT);
      Vector<String> value = new Vector<>();
      for (int i = 0; i < _configs.size(); i++) {
        Vector<String[]> v = _configs.elementAt(i);
        for (int j = 0; j < v.size(); j++) {
          String[] kv = v.elementAt(j);
          if (kv[0].toUpperCase(Locale.ROOT).equals(key)) {
            String foo = kv[1];
            if (foo != null) {
              value.remove(foo);
              value.addElement(foo);
            }
          }
        }
      }
      String[] result = new String[value.size()];
      value.toArray(result);
      return result;
    }

    @Override
    public String getHostname() {
      return find("Hostname");
    }

    @Override
    public String getUser() {
      return find("User");
    }

    @Override
    public int getPort() {
      String foo = find("Port");
      int port = -1;
      // Port is not required and we don't want to log a failure if its simply missing from the
      // OpenSSH config
      if (foo != null) {
        try {
          port = Integer.parseInt(foo);
        } catch (NumberFormatException e) {
          logError("Port", e);
        }
      }
      return port;
    }

    @Override
    public String getValue(String key) {
      if (key.equals("compression.s2c") || key.equals("compression.c2s")) {
        String foo = find(key);
        if (foo == null || foo.equals("no"))
          return "none,zlib@openssh.com,zlib";
        return "zlib@openssh.com,zlib,none";
      }
      return find(key);
    }

    @Override
    public String[] getValues(String key) {
      return multiFind(key);
    }
  }
}
