package com.jcraft.jsch;

final class JavaVersion {

  static int getVersion() {
    return Runtime.version().major();
  }
}
