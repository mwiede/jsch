package com.jcraft.jsch;

import ch.qos.logback.core.read.ListAppender;

public class ListAppender2<E> extends ListAppender<E> {

  @Override
  protected void append(E e) {
    // Avoid append messages after appender is stopped to avoid ConcurrentModificationException's
    // when examining the List of events.
    if (super.started) {
      super.append(e);
    }
  }
}
