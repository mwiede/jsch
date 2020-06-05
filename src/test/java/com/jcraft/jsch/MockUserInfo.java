package com.jcraft.jsch;

import java.util.ArrayList;
import java.util.List;

public class MockUserInfo implements UserInfo {

  private final List<String> messages;

  public MockUserInfo() {
    messages = new ArrayList<>();
  }

  @Override
  public String getPassphrase() {
    return "";
  }

  @Override
  public String getPassword() {
    return "";
  }

  @Override
  public boolean promptPassword(String message) {
    messages.add(message);
    return false;
  }

  @Override
  public boolean promptPassphrase(String message) {
    messages.add(message);
    return false;
  }

  @Override
  public boolean promptYesNo(String message) {
    messages.add(message);
    return false;
  }

  @Override
  public void showMessage(String message) {
    messages.add(message);
  }

  public List<String> getMessages() {
    return messages;
  }
}
