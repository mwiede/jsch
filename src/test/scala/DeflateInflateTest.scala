/* -*-mode:scala; c-basic-offset:2; indent-tabs-mode:nil -*- */
package com.jcraft.jsch.jzlib

import org.scalatest._
import org.scalatest.flatspec._
import matchers.should._

import JZlib._

class DeflateInflateTest extends AnyFlatSpec with BeforeAndAfter with Matchers {
  private val comprLen = 40000
  private val uncomprLen = comprLen
  private var compr:Array[Byte] = _
  private var uncompr:Array[Byte] = _

  private var deflater: Deflater = _
  private var inflater: Inflater = _
  private var err: Int = _

  before {
    compr = new Array[Byte](comprLen)
    uncompr = new Array[Byte](uncomprLen)

    deflater = new Deflater
    inflater = new Inflater

    err = Z_OK
  }

  after {
  }

  behavior of "Deflter and Inflater"

  it can "deflate and infate data in the large buffer." in {
    err = deflater.init(Z_BEST_SPEED)
    err should equal (Z_OK)

    deflater.setInput(uncompr)
    deflater.setOutput(compr)

    err = deflater.deflate(Z_NO_FLUSH)
    err should equal (Z_OK)

    deflater.avail_in should equal (0)

    deflater.params(Z_NO_COMPRESSION, Z_DEFAULT_STRATEGY)
    deflater.setInput(compr)
    deflater.avail_in = comprLen/2 

    err = deflater.deflate(Z_NO_FLUSH)
    err should equal (Z_OK)

    deflater.params(Z_BEST_COMPRESSION, Z_FILTERED)
    deflater.setInput(uncompr)
    deflater.avail_in = uncomprLen

    err = deflater.deflate(Z_NO_FLUSH)
    err should equal (Z_OK)

    err = deflater.deflate(JZlib.Z_FINISH)
    err should equal (Z_STREAM_END)

    err = deflater.end
    err should equal (Z_OK)

    inflater.setInput(compr)

    err = inflater.init
    err should equal (Z_OK)

    var loop = true
    while(loop) {
      inflater.setOutput(uncompr)
      err = inflater.inflate(Z_NO_FLUSH)
      if(err == Z_STREAM_END) loop = false
      else err should equal (Z_OK)
    }

    err = inflater.end
    err should equal (Z_OK)

    val total_out = inflater.total_out.asInstanceOf[Int]

    total_out should equal (2*uncomprLen + comprLen/2)
  }

  it can "deflate and infate data in the small buffer." in {
    val data = "hello, hello!".getBytes

    err = deflater.init(Z_DEFAULT_COMPRESSION)
    err should equal (Z_OK)

    deflater.setInput(data)
    deflater.setOutput(compr)

    while(deflater.total_in < data.length &&
          deflater.total_out < comprLen){
      deflater.avail_in = 1
      deflater.avail_out = 1
      err = deflater.deflate(Z_NO_FLUSH)
      err should equal (Z_OK)
    }

    do {
      deflater.avail_out = 1
      err = deflater.deflate(Z_FINISH)
    }
    while(err != Z_STREAM_END)

    err = deflater.end
    err should equal (Z_OK)

    inflater.setInput(compr)
    inflater.setOutput(uncompr)

    err = inflater.init
    err should equal (Z_OK)

    var loop = true
    while(inflater.total_out<uncomprLen &&
          inflater.total_in<comprLen && 
          loop) {
      inflater.avail_in = 1 // force small buffers
      inflater.avail_out = 1 // force small buffers
      err = inflater.inflate(Z_NO_FLUSH)
      if(err == Z_STREAM_END) loop = false
      else err should equal (Z_OK)
    }

    err = inflater.end
    err should equal (Z_OK)

    val total_out = inflater.total_out.asInstanceOf[Int]
    val actual = new Array[Byte](total_out)
    System.arraycopy(uncompr, 0, actual, 0, total_out)

    actual should equal (data)
  }

  it should "support the dictionary." in {
    val hello = "hello".getBytes
    val dictionary = "hello, hello!".getBytes

    err = deflater.init(Z_DEFAULT_COMPRESSION)
    err should equal (Z_OK)

    deflater.setDictionary(dictionary, dictionary.length)
    err should equal (Z_OK)

    val dictID = deflater.getAdler

    deflater.setInput(hello)
    deflater.setOutput(compr)

    err = deflater.deflate(Z_FINISH)
    err should equal (Z_STREAM_END)

    err = deflater.end
    err should equal (Z_OK)

    err = inflater.init
    err should equal (Z_OK)

    inflater.setInput(compr)
    inflater.setOutput(uncompr)

    var loop = true
    do {
      err = inflater.inflate(JZlib.Z_NO_FLUSH)
      err match {
        case Z_STREAM_END =>
          loop = false
        case Z_NEED_DICT =>
          dictID should equal (inflater.getAdler)
          err = inflater.setDictionary(dictionary, dictionary.length)
          err should equal (Z_OK)
        case _ =>
          err should equal (Z_OK)
      }
    }
    while(loop)

    err = inflater.end
    err should equal (Z_OK)

    val total_out = inflater.total_out.asInstanceOf[Int]
    val actual = new Array[Byte](total_out)
    System.arraycopy(uncompr, 0, actual, 0, total_out)

    actual should equal (hello)
  }

  it should "support the sync." in {
    val hello = "hello".getBytes

    err = deflater.init(Z_DEFAULT_COMPRESSION)
    err should equal (Z_OK)

    deflater.setInput(hello)
    deflater.avail_in = 3
    deflater.setOutput(compr)

    err = deflater.deflate(Z_FULL_FLUSH)
    err should equal (Z_OK)

    compr(3) = (compr(3) + 1).asInstanceOf[Byte]
    deflater.avail_in = hello.length - 3

    err = deflater.deflate(Z_FINISH)
    err should equal (Z_STREAM_END)
    val comprLen= deflater.total_out.asInstanceOf[Int]

    err = deflater.end
    err should equal (Z_OK)

    err = inflater.init
    err should equal (Z_OK)

    inflater.setInput(compr)
    inflater.avail_in = 2

    inflater.setOutput(uncompr)

    err = inflater.inflate(JZlib.Z_NO_FLUSH)
    err should equal (Z_OK)

    inflater.avail_in = comprLen-2
    err = inflater.sync

    err = inflater.inflate(Z_FINISH)
    err should equal (Z_DATA_ERROR)

    err = inflater.end
    err should equal (Z_OK)

    val total_out = inflater.total_out.asInstanceOf[Int]
    val actual = new Array[Byte](total_out)
    System.arraycopy(uncompr, 0, actual, 0, total_out)

    "hel"+new String(actual) should equal (new String(hello))
  }

  behavior of "Inflater"

  it can "inflate gzip data." in {
    val hello = "foo".getBytes
    val data = List(0x1f, 0x8b, 0x08, 0x18, 0x08, 0xeb, 0x7a, 0x0b, 0x00, 0x0b,
                    0x58, 0x00, 0x59, 0x00, 0x4b, 0xcb, 0xcf, 0x07, 0x00, 0x21,
                    0x65, 0x73, 0x8c, 0x03, 0x00, 0x00, 0x00).
                    map(_.asInstanceOf[Byte]).
                    toArray

    err = inflater.init(15 + 32)
    err should equal (Z_OK)

    inflater.setInput(data)
    inflater.setOutput(uncompr)

    val comprLen = data.length

    var loop = true
    while(inflater.total_out<uncomprLen &&
          inflater.total_in<comprLen && 
          loop) {
      err = inflater.inflate(Z_NO_FLUSH)
      if(err == Z_STREAM_END) loop = false
      else err should equal (Z_OK)
    }

    err = inflater.end
    err should equal (Z_OK)

    val total_out = inflater.total_out.asInstanceOf[Int]
    val actual = new Array[Byte](total_out)
    System.arraycopy(uncompr, 0, actual, 0, total_out)

    actual should equal (hello)
  }

  behavior of "Inflater and Deflater"

  it can "support gzip data." in {
    val data = "hello, hello!".getBytes

    err = deflater.init(Z_DEFAULT_COMPRESSION, 15+16)
    err should equal (Z_OK)

    deflater.setInput(data)
    deflater.setOutput(compr)

    while(deflater.total_in < data.length &&
          deflater.total_out < comprLen){
      deflater.avail_in = 1
      deflater.avail_out = 1
      err = deflater.deflate(Z_NO_FLUSH)
      err should equal (Z_OK)
    }

    do {
      deflater.avail_out = 1
      err = deflater.deflate(Z_FINISH)
    }
    while(err != Z_STREAM_END)

    err = deflater.end
    err should equal (Z_OK)

    inflater.setInput(compr)
    inflater.setOutput(uncompr)

    err = inflater.init(15 + 32)
    err should equal (Z_OK)

    var loop = true
    while(inflater.total_out<uncomprLen &&
          inflater.total_in<comprLen && 
          loop) {
      inflater.avail_in = 1 // force small buffers
      inflater.avail_out = 1 // force small buffers
      err = inflater.inflate(Z_NO_FLUSH)
      if(err == Z_STREAM_END) loop = false
      else err should equal (Z_OK)
    }

    err = inflater.end
    err should equal (Z_OK)

    val total_out = inflater.total_out.asInstanceOf[Int]
    val actual = new Array[Byte](total_out)
    System.arraycopy(uncompr, 0, actual, 0, total_out)

    actual should equal (data) 
  }
}
