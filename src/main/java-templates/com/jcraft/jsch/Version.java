package com.jcraft.jsch;

final class Version {

  private static final String VERSION = "${versionWithoutMinus}";

  static String getVersion() {
    return VERSION;
  }
}
