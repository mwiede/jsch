package com.jcraft.jsch;

import com.jcraft.jsch.annotations.SuppressForbiddenApi;

final class JavaVersion {

  @SuppressForbiddenApi("jdk-deprecated")
  static int getVersion() {
    return Runtime.version().major();
  }
}
