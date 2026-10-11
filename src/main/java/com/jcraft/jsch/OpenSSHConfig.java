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
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
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
 * <li>Match (all, host, originalhost, user, localuser)</li>
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
        return new OpenSSHConfig(br, userSshDirectory());
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
      return new OpenSSHConfig(br, includeBase, activeFiles);
    }
  }

  private static Path userSshDirectory() {
    return Paths.get(System.getProperty("user.home"), ".ssh");
  }

  OpenSSHConfig(BufferedReader br, Path includeBase) throws IOException {
    this(br, includeBase, new HashSet<>());
  }

  private OpenSSHConfig(BufferedReader br, Path includeBase, Set<Path> activeFiles)
      throws IOException {
    Section global = new Section("", null, Collections.emptyList(), Collections.emptyList());
    sections.add(global);
    parse(br, includeBase, activeFiles, 0, global, Collections.emptyList(),
        Collections.emptyList());
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

  private final Vector<Section> sections = new Vector<>();

  private void parse(BufferedReader br, Path includeBase, Set<Path> activeFiles, int depth,
      Section current, List<String> enclosingHosts, List<MatchExpression> enclosingMatches)
      throws IOException {
    String line;
    while ((line = br.readLine()) != null) {
      current = parseLine(line, includeBase, activeFiles, depth, current, enclosingHosts,
          enclosingMatches);
    }
  }

  private Section parseLine(String line, Path includeBase, Set<Path> activeFiles, int depth,
      Section current, List<String> enclosingHosts, List<MatchExpression> enclosingMatches)
      throws IOException {
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
    String value = stripComment(keyValue[1].trim());
    if (value.startsWith("=")) {
      value = stripComment(value.substring(1).trim());
    }
    if (key.equalsIgnoreCase("Host")) {
      if (value.isEmpty()) {
        throw new IOException("Host requires at least one pattern");
      }
      Section next = new Section(value, null, enclosingHosts, enclosingMatches);
      sections.add(next);
      return next;
    }
    if (key.equalsIgnoreCase("Match")) {
      Section next = new Section("", parseMatch(value), enclosingHosts, enclosingMatches);
      sections.add(next);
      return next;
    }
    if (key.equalsIgnoreCase("Include")) {
      includeFiles(value, includeBase, activeFiles, depth, current);
      Section next = new Section(current.host, current.match, enclosingHosts, enclosingMatches);
      sections.add(next);
      return next;
    }
    current.options.addElement(new String[] {key, value});
    return current;
  }

  /**
   * Drops a trailing comment like OpenSSH: an unquoted, unescaped {@code #} that starts a word ends
   * the value, while one inside a word ({@code h#1}) or inside quotes is kept.
   */
  private static String stripComment(String value) {
    char quote = 0;
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch == '\\' && i + 1 < value.length() && isEscapable(value.charAt(i + 1), quote)) {
        i++;
      } else if (quote != 0) {
        if (ch == quote) {
          quote = 0;
        }
      } else if (ch == '"' || ch == '\'') {
        quote = ch;
      } else if (ch == '#' && (i == 0 || Character.isWhitespace(value.charAt(i - 1)))) {
        return value.substring(0, i).trim();
      }
    }
    return value;
  }

  private static boolean isEscapable(char next, char quote) {
    return next == '\\' || next == '"' || next == '\'' || (quote == 0 && next == ' ');
  }

  private void includeFiles(String value, Path includeBase, Set<Path> activeFiles, int depth,
      Section current) throws IOException {
    List<String> enclosingHosts = new ArrayList<>(current.enclosingHosts);
    List<MatchExpression> enclosingMatches = new ArrayList<>(current.enclosingMatches);
    if (!current.host.isEmpty()) {
      enclosingHosts.add(current.host);
    }
    if (current.match != null) {
      enclosingMatches.add(current.match);
    }
    for (String pattern : includeArguments(value)) {
      for (Path path : expandInclude(pattern, includeBase)) {
        includeFile(path, includeBase, activeFiles, depth, enclosingHosts, enclosingMatches);
      }
    }
  }

  private void includeFile(Path path, Path includeBase, Set<Path> activeFiles, int depth,
      List<String> enclosingHosts, List<MatchExpression> enclosingMatches) throws IOException {
    if (depth >= 16) {
      throw new IOException("Too many recursive configuration includes: " + path);
    }
    Path realPath = path.toRealPath();
    if (!activeFiles.add(realPath)) {
      throw new IOException("Recursive configuration include: " + path);
    }
    try (BufferedReader included = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
      Section includedContext = new Section("", null, enclosingHosts, enclosingMatches);
      sections.add(includedContext);
      parse(included, includeBase, activeFiles, depth + 1, includedContext, enclosingHosts,
          enclosingMatches);
    } finally {
      activeFiles.remove(realPath);
    }
  }

  private static List<String> includeArguments(String value) throws IOException {
    IncludeArgumentParser parser = new IncludeArgumentParser();
    for (int i = 0; i < value.length(); i++) {
      if (!parser.accept(value.charAt(i), i + 1 < value.length() ? value.charAt(i + 1) : 0)) {
        break;
      }
    }
    return parser.finish(value);
  }

  private static MatchExpression parseMatch(String value) throws IOException {
    if (value.isEmpty()) {
      throw new IOException("Match requires at least one criterion");
    }
    List<String> arguments = includeArguments(value);
    List<MatchCriterion> criteria = new ArrayList<>();
    for (int i = 0; i < arguments.size(); i++) {
      String attribute = arguments.get(i);
      boolean negated = attribute.startsWith("!");
      if (negated) {
        attribute = attribute.substring(1);
      }
      int equals = attribute.indexOf('=');
      String pattern = equals < 0 ? null : attribute.substring(equals + 1);
      String type =
          (equals < 0 ? attribute : attribute.substring(0, equals)).toLowerCase(Locale.ROOT);
      if (type.equals("all")) {
        if (arguments.size() != 1) {
          throw new IOException("Match all cannot be combined with other criteria");
        }
        criteria.add(new MatchCriterion(type, null, negated));
        continue;
      }
      if (!type.equals("host") && !type.equals("originalhost") && !type.equals("user")
          && !type.equals("localuser")) {
        throw new IOException("Unsupported Match criterion: " + type);
      }
      if (pattern == null && ++i < arguments.size()) {
        pattern = arguments.get(i);
      }
      if (pattern == null || pattern.isEmpty()) {
        throw new IOException("Missing Match pattern for " + type);
      }
      criteria.add(new MatchCriterion(type, pattern, negated));
    }
    return new MatchExpression(criteria);
  }

  private static final class MatchCriterion {
    final String type;
    final String pattern;
    final boolean negated;

    MatchCriterion(String type, String pattern, boolean negated) {
      this.type = type;
      this.pattern = pattern;
      this.negated = negated;
    }

    boolean matches(String originalHost, String effectiveHost, String remoteUser) {
      String candidate;
      switch (type) {
        case "all":
          return !negated;
        case "host":
          candidate = effectiveHost;
          break;
        case "originalhost":
          candidate = originalHost;
          break;
        case "user":
          candidate = remoteUser;
          break;
        case "localuser":
          candidate = System.getProperty("user.name");
          break;
        default:
          return false;
      }
      boolean matched =
          candidate != null && matchesPatternList(pattern, Util.str2byte(candidate), ",");
      return negated ? !matched : matched;
    }
  }

  private static final class MatchExpression {
    final List<MatchCriterion> criteria;

    MatchExpression(List<MatchCriterion> criteria) {
      this.criteria = criteria;
    }

    boolean matches(String originalHost, String effectiveHost, String remoteUser) {
      for (MatchCriterion criterion : criteria) {
        if (!criterion.matches(originalHost, effectiveHost, remoteUser)) {
          return false;
        }
      }
      return true;
    }
  }

  private static final class IncludeArgumentParser {
    private final List<String> paths = new ArrayList<>();
    private final StringBuilder path = new StringBuilder();
    private char quote;
    private boolean escaped;

    boolean accept(char ch, char next) {
      if (escaped) {
        path.append(ch);
        escaped = false;
      } else if (ch == '\\') {
        if (next == '\\' || next == '"' || next == '\'' || (quote == 0 && next == ' ')) {
          escaped = true;
        } else {
          path.append(ch);
        }
      } else if (quote != 0) {
        if (ch == quote) {
          quote = 0;
        } else {
          path.append(ch);
        }
      } else if (ch == '"' || ch == '\'') {
        quote = ch;
      } else if (Character.isWhitespace(ch)) {
        flush();
      } else if (ch == '#' && path.length() == 0) {
        return false;
      } else {
        path.append(ch);
      }
      return true;
    }

    List<String> finish(String value) throws IOException {
      if (quote != 0) {
        throw new IOException("Unterminated Include path: " + value);
      }
      flush();
      if (paths.isEmpty()) {
        throw new IOException("Include requires at least one path");
      }
      return paths;
    }

    private void flush() {
      if (path.length() > 0) {
        paths.add(path.toString());
        path.setLength(0);
      }
    }
  }

  private static List<Path> expandInclude(String pattern, Path includeBase) throws IOException {
    String name = pattern;
    if (name.startsWith("~") && !name.equals("~") && !name.startsWith("~/")) {
      throw new IOException("Unsupported Include home path: " + pattern);
    }
    if (name.equals("~") || name.startsWith("~/")) {
      name = System.getProperty("user.home") + name.substring(1);
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
      Path path = Paths.get(pattern);
      if (!path.isAbsolute()) {
        path = includeBase.resolve(path);
      }
      return Files.isRegularFile(path) ? Collections.singletonList(path) : Collections.emptyList();
    }

    int separator = lastSeparatorBefore(pattern, wildcard);
    Path prefix = separator < 0 ? includeBase : Paths.get(pattern.substring(0, separator + 1));
    if (!prefix.isAbsolute()) {
      prefix = includeBase.resolve(prefix);
    }
    List<Path> candidates = new ArrayList<>();
    candidates.add(prefix);
    for (String segment : splitSegments(pattern.substring(separator + 1))) {
      List<Path> next = new ArrayList<>();
      if (firstWildcard(segment) < 0) {
        for (Path directory : candidates) {
          Path path = directory.resolve(segment);
          if (Files.exists(path)) {
            next.add(path);
          }
        }
      } else {
        PathMatcher matcher;
        try {
          matcher = prefix.getFileSystem()
              .getPathMatcher("glob:" + segment.replace("{", "\\{").replace("}", "\\}"));
        } catch (IllegalArgumentException e) {
          throw new IOException("Invalid Include pattern: " + pattern, e);
        }
        for (Path directory : candidates) {
          if (!Files.isDirectory(directory)) {
            continue;
          }
          try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
            for (Path entry : entries) {
              String filename = entry.getFileName().toString();
              if ((segment.startsWith(".") || !filename.startsWith("."))
                  && matcher.matches(entry.getFileName())) {
                next.add(entry);
              }
            }
          } catch (IOException e) {
            // An unreadable branch does not prevent other glob matches.
          }
        }
      }
      candidates = next;
      if (candidates.isEmpty()) {
        break;
      }
    }
    return candidates.stream().filter(Files::isRegularFile)
        .sorted(Comparator.comparing(Path::toString)).collect(Collectors.toList());
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
      if (ch == '/' || (java.io.File.separatorChar == '\\' && ch == '\\')) {
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
          || (java.io.File.separatorChar == '\\' && pattern.charAt(i) == '\\')) {
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

      byte[] _host = Util.str2byte(host);
      String effectiveHost = host;
      String remoteUser = user != null ? user : System.getProperty("user.name");
      boolean hostnameSet = false;
      boolean userSet = user != null;
      Map<MatchExpression, Boolean> matchResults = new IdentityHashMap<>();
      for (Section section : sections) {
        boolean matches = section.host.isEmpty() || matchesHostPatterns(section.host, _host);
        for (String enclosingHost : section.enclosingHosts) {
          matches &= matchesHostPatterns(enclosingHost, _host);
        }
        if (section.match != null) {
          matches &= matchOnce(section.match, host, effectiveHost, remoteUser, matchResults);
        }
        for (MatchExpression enclosingMatch : section.enclosingMatches) {
          matches &= matchOnce(enclosingMatch, host, effectiveHost, remoteUser, matchResults);
        }
        if (matches) {
          _configs.addElement(section.options);
          for (String[] option : section.options) {
            if (!hostnameSet && option[0].equalsIgnoreCase("HostName")) {
              effectiveHost = option[1].replace("%h", host);
              hostnameSet = true;
            } else if (!userSet && option[0].equalsIgnoreCase("User")) {
              remoteUser = option[1];
              userSet = true;
            }
          }
        }
      }
    }

    private boolean matchOnce(MatchExpression expression, String originalHost, String effectiveHost,
        String remoteUser, Map<MatchExpression, Boolean> results) {
      Boolean result = results.get(expression);
      if (result == null) {
        result = expression.matches(originalHost, effectiveHost, remoteUser);
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
