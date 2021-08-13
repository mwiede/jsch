/* -*-mode:scala; c-basic-offset:2; indent-tabs-mode:nil -*- */
package com.jcraft.jsch.jzlib

import org.scalatest._
import org.scalatest.flatspec._
import matchers.should._

import scala.language.reflectiveCalls

import java.io._
import java.util.zip.CheckedOutputStream
import java.util.zip.CheckedInputStream
import java.util.zip.{GZIPInputStream => juzGZIPInputStream}
import java.util.zip.{CRC32 => juzCRC32}

import JZlib._

class GZIPIOStreamTest extends AnyFlatSpec with BeforeAndAfter with Matchers {

  before {
  }

  after {
  }

  behavior of "GZIPOutputStream and GZIPInputStream"

  it can "deflate and infate data." in {

    val comment = "hi"
    val name = "/tmp/foo"

    val content = "hello".getBytes

    val baos = new ByteArrayOutputStream
    val gos = new GZIPOutputStream(baos)

    gos.setComment(comment)
    gos.setName(name)
 
    gos.write(content)
    gos.close

    val bais = new ByteArrayInputStream(baos.toByteArray)
    val gis = new GZIPInputStream(bais)

    val buf = new Array[Byte](1024)
    val i = gis.read(buf)

    content.length should equal(i)
    (0 until i) foreach { i =>
      content(i).asInstanceOf[Byte] should equal(buf(i).asInstanceOf[Byte])
    }

    comment should equal(gis.getComment)
    name should equal(gis.getName)

    val crc32 = new CRC32
    crc32.update(content, 0, content.length)

    crc32.getValue should equal(gis.getCRC.asInstanceOf[Long])
  }

  behavior of "GZIPOutputStream"

  // https://github.com/ymnk/jzlib/issues/9
  // https://github.com/jglick/jzlib-9-demo
  it can "deflate some file without AIOOBE." in {
    val pos = new PipedOutputStream()
    val pis = new PipedInputStream(pos)
    val csOut = new juzCRC32()
    val gos = new GZIPOutputStream(pos)
    val cos = new CheckedOutputStream(gos, csOut)

    val t = new Thread() {
      override def run = {
        val fail = "/jzlib.fail.gz".fromResource
        val fis = new juzGZIPInputStream(new ByteArrayInputStream(fail))
        fis -> cos
        cos.close()
      }
    }
    t.start();

    val gis = new GZIPInputStream(pis)
    val csIn = new juzCRC32();
    new CheckedInputStream(gis, csIn) -> new ByteArrayOutputStream()

    t.join()

    csIn.getValue() should equal(csOut.getValue)
  }
}
