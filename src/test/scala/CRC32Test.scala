/* -*-mode:scala; c-basic-offset:2; indent-tabs-mode:nil -*- */
package com.jcraft.jsch.jzlib

import org.scalatest._
import org.scalatest.flatspec._
import matchers.should._

import java.util.zip.{CRC32 => juzCRC32}

class CRC32Test extends AnyFlatSpec with BeforeAndAfter with Matchers {
  private var crc: CRC32 = _

  before {
    crc = new CRC32
  }

  after {
  }

  behavior of "CRC32"

  it must "be compatible with java.util.zip.CRC32." in {
    val buf1 = randombuf(1024)
    val juza = new juzCRC32
    val expected = {
      juza.update(buf1, 0, buf1.length)
      juza.getValue
    }
    val actual = getValue(List(buf1))

    actual should equal (expected)
  }

  it can "copy itself." in {
    val buf1 = randombuf(1024)
    val buf2 = randombuf(1024)

    val crc1 = new CRC32
    
    crc1.update(buf1, 0, buf1.length)

    val crc2 = crc1.copy

    crc1.update(buf2, 0, buf1.length)
    crc2.update(buf2, 0, buf1.length)

    val expected = crc1.getValue
    val actual = crc2.getValue

    actual should equal (expected)
  }

  it can "combine crc values." in {

    val buf1 = randombuf(1024)
    val buf2 = randombuf(1024)

    val crc1 = getValue(List(buf1))
    val crc2 = getValue(List(buf2))
    val expected = getValue(List(buf1, buf2))

    val actual = CRC32.combine(crc1, crc2, buf2.length)

    actual should equal (expected)
  }

  private def getValue(buf:Seq[Array[Byte]]) = synchronized {
    crc.reset
    buf.foreach { b => crc.update(b, 0, b.length) }
    crc.getValue
  }
}
