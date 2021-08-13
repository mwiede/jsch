/* -*-mode:scala; c-basic-offset:2; indent-tabs-mode:nil -*- */
package com.jcraft.jsch

import scala.language.implicitConversions
import scala.language.postfixOps
import scala.language.reflectiveCalls

import java.io._

package object jzlib {
  implicit def readIS(is: InputStream) = new {
      def ->(out: OutputStream)
            (implicit buf: Array[Byte] = new Array[Byte](1024)) = {
      LazyList.
        continually(is.read(buf)).
        takeWhile(-1 !=).
        foreach(i => out.write(buf, 0, i))
      is.close
    }
  }

  // reading a resource file 
  implicit def fromResource(str: String ) = new {
    def fromResource: Array[Byte] =
      io.Source.
         fromURL(getClass.getResource(str))(io.Codec.ISO8859).
         map(_.toByte).
         toArray
  }

  implicit def readArray(is: Array[Byte]) = new {
      def ->(out: OutputStream)(implicit buf: Array[Byte]) = {
        new ByteArrayInputStream(is) -> (out)
    }
  }

  def randombuf(n: Int) = (0 to n).map{ _ =>
    util.Random.nextLong().asInstanceOf[Byte] 
  }.toArray
}
