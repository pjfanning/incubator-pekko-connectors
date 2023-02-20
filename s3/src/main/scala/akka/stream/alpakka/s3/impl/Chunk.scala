/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * license agreements; and to You under the Apache License, version 2.0:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * This file is part of the Apache Pekko project, derived from Akka.
 */

/*
 * Copyright (C) since 2016 Lightbend Inc. <https://www.lightbend.com>
 */

package akka.stream.alpakka.s3.impl

import akka.stream.scaladsl.Source
import akka.NotUsed
import akka.annotation.InternalApi
import akka.http.scaladsl.model.{ ContentTypes, HttpEntity, RequestEntity }
import akka.util.ByteString

/**
 * Internal Api
 */
@InternalApi private[impl] sealed trait Chunk {
  def asEntity(): RequestEntity
  def size: Int
}

@InternalApi private[impl] final case class DiskChunk(data: Source[ByteString, NotUsed], size: Int) extends Chunk {
  def asEntity(): RequestEntity = HttpEntity(ContentTypes.`application/octet-stream`, size, data)
}

@InternalApi private[impl] final case class MemoryChunk(data: ByteString) extends Chunk {
  def asEntity(): RequestEntity = HttpEntity.Strict(ContentTypes.`application/octet-stream`, data)
  def size: Int = data.size
}
