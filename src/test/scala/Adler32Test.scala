/* -*-mode:scala; c-basic-offset:2; indent-tabs-mode:nil -*- */
package com.jcraft.jsch.jzlib

import org.scalatest._
import org.scalatest.flatspec._
import matchers.should._

import java.util.zip.{Adler32 => juzAdler32}

class Adler32Test extends AnyFlatSpec with BeforeAndAfter with Matchers {
  private var adler: Adler32 = _

  before {
    adler = new Adler32
  }

  after {
  }

  behavior of "Adler32"

  it must "be compatible with java.util.zip.Adler32." in {
    val buf1 = randombuf(1024)
    val juza = new juzAdler32
    val expected = {
      juza.update(buf1, 0, buf1.length)
      juza.getValue
    }
    val actual = getValue(List(buf1));

    actual should equal (expected)
  }

  it can "copy itself." in {
    val buf1 = randombuf(1024)
    val buf2 = randombuf(1024)

    val adler1 = new Adler32
    
    adler1.update(buf1, 0, buf1.length);

    val adler2 = adler1.copy

    adler1.update(buf2, 0, buf1.length);
    adler2.update(buf2, 0, buf1.length);

    val expected = adler1.getValue
    val actual = adler2.getValue

    actual should equal (expected)
  }

  it can "combine adler values." in {

    val buf1 = randombuf(1024)
    val buf2 = randombuf(1024)

    val adler1 = getValue(List(buf1));
    val adler2 = getValue(List(buf2));
    val expected = getValue(List(buf1, buf2));

    val actual = Adler32.combine(adler1, adler2, buf2.length)

    actual should equal (expected)
  }

  private def getValue(buf:Seq[Array[Byte]]) = synchronized {
    adler.reset
    buf.foreach { b => adler.update(b, 0, b.length) }
    adler.getValue
  }
}
