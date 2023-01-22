/* -*-mode:scala; c-basic-offset:2; indent-tabs-mode:nil -*- */
package com.jcraft.jsch.jzlib

import org.scalatest._
import org.scalatest.flatspec._
import matchers.should._

import scala.language.reflectiveCalls

import java.io.{ByteArrayOutputStream => BAOS, ByteArrayInputStream => BAIS}

import JZlib._

class WrapperTypeTest extends AnyFlatSpec with BeforeAndAfter with Matchers {
  private val data = "hello, hello!".getBytes

  private val comprLen = 40000
  private val uncomprLen = comprLen
  private var compr:Array[Byte] = _
  private var uncompr:Array[Byte] = _
  private var err: Int = _

  private val cases = /* success */     /* fail */ 
    List((W_ZLIB, (List(W_ZLIB, W_ANY), List(W_GZIP, W_NONE))),
         (W_GZIP, (List(W_GZIP, W_ANY), List(W_ZLIB, W_NONE))),
         (W_NONE, (List(W_NONE, W_ANY), List(W_ZLIB, W_GZIP))))

  before {
    compr = new Array[Byte](comprLen)
    uncompr = new Array[Byte](uncomprLen)

    err = Z_OK
  }

  after {
  }

  behavior of "Deflater"

  it can "detect data type of input." in {
    implicit val buf = compr

    cases foreach { case (iflag, (good, bad)) => 
      val baos = new BAOS
      val deflater = new Deflater(Z_DEFAULT_COMPRESSION, DEF_WBITS, 9, iflag)
      val gos = new DeflaterOutputStream(baos, deflater)
      data -> gos
      gos.close

      val deflated = baos.toByteArray

      good map { w =>
        val baos2 = new BAOS
        val inflater = new Inflater(w)
        new InflaterInputStream(new BAIS(deflated), inflater) -> baos2
        val data1 = baos2.toByteArray
        data1.length should equal (data.length)
        data1 should equal (data)
        import inflater._
        (avail_in, avail_out, total_in, total_out)
      } reduceLeft { (x, y) => x should equal (y); x }

      bad foreach { w =>
        val baos2 = new BAOS
        val inflater = new Inflater(w)
        try {
          new InflaterInputStream(new BAIS(deflated), inflater) -> baos2
          fail("unreachable")
        }
        catch {
          case e:java.io.IOException  =>
        }
      } 
    }
  } 

  behavior of "ZStream"

  it can "detect data type of input." in {
    cases foreach { case (iflag, (good, bad)) => 
      val deflater = new ZStream

      err = deflater.deflateInit(Z_BEST_SPEED, DEF_WBITS, 9, iflag)
      err should equal (Z_OK)

      deflate(deflater, data, compr)

      good foreach { w =>
        val inflater = inflate(compr, uncompr, w)
        val total_out = inflater.total_out.asInstanceOf[Int]
        new String(uncompr, 0, total_out) should equal (new String(data))
      }

      bad foreach { w =>
        inflate_fail(compr, uncompr, w)
      }
    }
  }

  behavior of "Deflater"

  it should "support wbits+32." in {

    var deflater = new Deflater
    err = deflater.init(Z_BEST_SPEED, DEF_WBITS, 9)
    err should equal (Z_OK)

    deflate(deflater, data, compr)

    var inflater = new Inflater
    err = inflater.init(DEF_WBITS + 32)
    err should equal (Z_OK)

    inflater.setInput(compr)

    var loop = true
    while(loop) {
      inflater.setOutput(uncompr)
      err = inflater.inflate(Z_NO_FLUSH)
      if(err == Z_STREAM_END) loop = false
      else err should equal (Z_OK)
    }
    err = inflater.end
    err should equal (Z_OK)

    var total_out = inflater.total_out.asInstanceOf[Int]
    new String(uncompr, 0, total_out) should equal (new String(data))

    deflater = new Deflater
    err = deflater.init(Z_BEST_SPEED, DEF_WBITS + 16, 9)
    err should equal (Z_OK)

    deflate(deflater, data, compr)

    inflater = new Inflater
    err = inflater.init(DEF_WBITS + 32)
    err should equal (Z_OK)

    inflater.setInput(compr)

    loop = true
    while(loop) {
      inflater.setOutput(uncompr)
      err = inflater.inflate(Z_NO_FLUSH)
      if(err == Z_STREAM_END) loop = false
      else err should equal (Z_OK)
    }
    err = inflater.end
    err should equal (Z_OK)

    total_out = inflater.total_out.asInstanceOf[Int]
    new String(uncompr, 0, total_out) should equal (new String(data))
  }

  private def deflate(deflater: ZStream,
                      data: Array[Byte], compr: Array[Byte]) = {
    deflater.setInput(data)
    deflater.setOutput(compr)

    err = deflater.deflate(JZlib.Z_FINISH)
    err should equal (Z_STREAM_END)

    err = deflater.end
    err should equal (Z_OK)
  }    

  private def inflate(compr: Array[Byte],
                      uncompr: Array[Byte],
                      w: WrapperType) = {
    val inflater = new ZStream
    err = inflater.inflateInit(w)
    err should equal (Z_OK)

    inflater.setInput(compr)

    var loop = true
    while(loop) {
      inflater.setOutput(uncompr)
      err = inflater.inflate(Z_NO_FLUSH)
      if(err == Z_STREAM_END) loop = false
      else err should equal (Z_OK)
    }
    err = inflater.end
    err should equal (Z_OK)

    inflater
  }

  private def inflate_fail(compr: Array[Byte],
                           uncompr: Array[Byte],
                           w: WrapperType) = {
    val inflater = new ZStream

    err = inflater.inflateInit(w)
    err should equal (Z_OK)

    inflater.setInput(compr)

    var loop = true
    while(loop) {
      inflater.setOutput(uncompr)
      err = inflater.inflate(Z_NO_FLUSH)
      if(err == Z_STREAM_END) loop = false
      else {
        err should equal (Z_DATA_ERROR)
        loop = false
      }
    }
  }
}
