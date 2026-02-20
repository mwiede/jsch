package com.jcraft.jsch;

final class JavaThreadId {

  static long get() {
    return Thread.currentThread().threadId();
  }
}
