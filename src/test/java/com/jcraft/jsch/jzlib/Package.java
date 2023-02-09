package com.jcraft.jsch.jzlib;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.util.Random;
import java.util.function.Consumer;
import java.util.function.Function;

public class Package {
  public static void readIS(InputStream is, OutputStream out, byte[] buf) throws IOException {
    int i;
    while ((i = is.read(buf)) != -1) {
      out.write(buf, 0, i);
    }
    is.close();
  }

  public static void readArray(byte[] is, OutputStream out, byte[] buf) throws IOException {
    readIS(new ByteArrayInputStream(is), out, buf);
  }

  public static byte[] randombuf(int n) {
    Random random = new Random();
    byte[] ret = new byte[n];
    random.nextBytes(ret);
    return ret;
  }

  public static <T> Consumer<T> uncheckedConsumer(IOConsumer<T> consumer) {
    return t -> {
      try {
        consumer.accept(t);
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    };
  }

  public static <T, R> Function<T, R> uncheckedFunction(IOFunction<T, R> function) {
    return t -> {
      try {
        return function.apply(t);
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    };
  }

  @FunctionalInterface
  public interface IOConsumer<T> {
    void accept(T t) throws IOException;
  }

  @FunctionalInterface
  public interface IOFunction<T, R> {
    R apply(T t) throws IOException;
  }
}
