package com.jcraft.jsch;

final class Version {

  private static final String VERSION = "${project.version}";

  static String getVersion() {
    return VERSION;
  }
}
