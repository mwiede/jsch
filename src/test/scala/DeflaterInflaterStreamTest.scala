/* -*-mode:scala; c-basic-offset:2; indent-tabs-mode:nil -*- */
package com.jcraft.jsch.jzlib

import org.scalatest._
import org.scalatest.flatspec._
import matchers.should._

import scala.language.reflectiveCalls

import java.io.{ByteArrayOutputStream => BAOS, ByteArrayInputStream => BAIS}

class DeflaterInflaterStreamTest extends AnyFlatSpec with BeforeAndAfter with Matchers {

  before {
  }

  after {
  }

  behavior of "Deflter and Inflater"

  it can "deflate and infate data one by one." in {
    val data1 = randombuf(1024)
    implicit val buf = new Array[Byte](1)

    val baos = new BAOS
    val gos = new DeflaterOutputStream(baos)
    data1 -> gos
    gos.close

    val baos2 = new BAOS
    new InflaterInputStream(new BAIS(baos.toByteArray)) -> baos2
    val data2 = baos2.toByteArray 

    data2.length should equal (data1.length)
    data2 should equal (data1)
  }

  behavior of "DeflterOutputStream and InflaterInputStream"

  it can "deflate and infate." in {

    (1 to 100 by 3).foreach { i =>

      implicit val buf = new Array[Byte](i)

      val data1 = randombuf(10240)

      val baos = new BAOS
      val gos = new DeflaterOutputStream(baos)
      data1 -> gos
      gos.close

      val baos2 = new BAOS
      new InflaterInputStream(new BAIS(baos.toByteArray)) -> baos2
      val data2 = baos2.toByteArray

      data2.length should equal (data1.length)
      data2 should equal (data1)
    }
  }

  behavior of "Deflter and Inflater"

  it can "deflate and infate nowrap data." in {

    (1 to 100 by 3).foreach { i =>

      implicit val buf = new Array[Byte](i)

      val data1 = randombuf(10240)

      val baos = new BAOS
      val deflater = new Deflater(JZlib.Z_DEFAULT_COMPRESSION,
                                 JZlib.DEF_WBITS,
                                 true)
      val gos = new DeflaterOutputStream(baos, deflater)
      data1 -> gos
      gos.close

      val baos2 = new BAOS
      val inflater = new Inflater(JZlib.DEF_WBITS, true)
      new InflaterInputStream(new BAIS(baos.toByteArray), inflater) -> baos2
      val data2 = baos2.toByteArray

      data2.length should equal (data1.length)
      data2 should equal (data1)
    }
  }

  it can "deflate and infate nowrap data with MAX_WBITS." in {
    implicit val buf = new Array[Byte](100)

    List(randombuf(10240),
         """{"color":2,"id":"EvLd4UG.CXjnk35o1e8LrYYQfHu0h.d*SqVJPoqmzXM::Ly::Snaps::Store::Commit"}""".getBytes) foreach { data1 =>

      val deflater = new Deflater(JZlib.Z_DEFAULT_COMPRESSION,
                                  JZlib.MAX_WBITS,
                                  true)

      val inflater = new Inflater(JZlib.MAX_WBITS, true)

      val baos = new BAOS
      val gos = new DeflaterOutputStream(baos, deflater)
      data1 -> gos
      gos.close

      val baos2 = new BAOS
      new InflaterInputStream(new BAIS(baos.toByteArray), inflater) -> baos2
      val data2 = baos2.toByteArray

      data2.length should equal (data1.length)
      data2 should equal (data1)
    }
  }
}
