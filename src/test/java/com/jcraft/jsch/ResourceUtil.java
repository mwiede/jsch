package com.jcraft.jsch;

import java.io.File;

public class ResourceUtil {
  public static String getResourceFile(Class<?> clazz, String fileName) {
    String path = clazz.getClassLoader().getResource(fileName).getFile();
    // Note: on Windows the returned path can be in the form: /C:/<path>
    // to strip the initial / in a platform independent way we need to
    // create a java.io.File and take it's absolute path
    return new File(path).getAbsolutePath();
  }
}
