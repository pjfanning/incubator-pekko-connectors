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

package org.apache.pekko.stream.connectors.couchbase.scaladsl

import org.apache.pekko
import pekko.NotUsed
import pekko.stream.connectors.couchbase.{
  CouchbaseDeleteFailure,
  CouchbaseDeleteResult,
  CouchbaseDeleteSuccess,
  CouchbaseSessionRegistry,
  CouchbaseSessionSettings,
  CouchbaseWriteFailure,
  CouchbaseWriteResult,
  CouchbaseWriteSettings,
  CouchbaseWriteSuccess
}
import pekko.stream.scaladsl.Flow
import com.couchbase.client.java.document.{ Document, JsonDocument }

import scala.concurrent.ExecutionContext

/**
 * Scala API: Factory methods for Couchbase flows.
 */
object CouchbaseFlow {

  /**
   * Create a flow to query Couchbase for by `id` and emit [[com.couchbase.client.java.document.JsonDocument JsonDocument]]s.
   */
  def fromId(sessionSettings: CouchbaseSessionSettings, bucketName: String): Flow[String, JsonDocument, NotUsed] =
    Flow
      .fromMaterializer { (materializer, _) =>
        val session = CouchbaseSessionRegistry(materializer.system).sessionFor(sessionSettings, bucketName)
        Flow[String]
          .mapAsync(1)(id => session.flatMap(_.get(id /* timeout? */ ))(materializer.system.dispatcher))
          .collect { case Some(doc) => doc }
      }
      .mapMaterializedValue(_ => NotUsed)

  /**
   * Create a flow to query Couchbase for by `id` and emit documents of the given class.
   */
  def fromId[T <: Document[_]](sessionSettings: CouchbaseSessionSettings,
      bucketName: String,
      target: Class[T]): Flow[String, T, NotUsed] =
    Flow
      .fromMaterializer { (materializer, _) =>
        val session = CouchbaseSessionRegistry(materializer.system).sessionFor(sessionSettings, bucketName)
        Flow[String]
          .mapAsync(1)(id => session.flatMap(_.get(id /* timeout? */, target))(materializer.system.dispatcher))
          .collect { case Some(doc) => doc }
      }
      .mapMaterializedValue(_ => NotUsed)

  /**
   * Create a flow to update or insert a Couchbase [[com.couchbase.client.java.document.JsonDocument JsonDocument]].
   */
  def upsert(sessionSettings: CouchbaseSessionSettings,
      writeSettings: CouchbaseWriteSettings,
      bucketName: String): Flow[JsonDocument, JsonDocument, NotUsed] =
    Flow
      .fromMaterializer { (materializer, _) =>
        val session = CouchbaseSessionRegistry(materializer.system).sessionFor(sessionSettings, bucketName)
        Flow[JsonDocument]
          .mapAsync(writeSettings.parallelism)(doc =>
            session.flatMap(_.upsert(doc, writeSettings))(materializer.system.dispatcher))
      }
      .mapMaterializedValue(_ => NotUsed)

  /**
   * Create a flow to update or insert a Couchbase document of the given class.
   */
  def upsertDoc[T <: Document[_]](sessionSettings: CouchbaseSessionSettings,
      writeSettings: CouchbaseWriteSettings,
      bucketName: String): Flow[T, T, NotUsed] =
    Flow
      .fromMaterializer { (materializer, _) =>
        val session = CouchbaseSessionRegistry(materializer.system).sessionFor(sessionSettings, bucketName)
        Flow[T]
          .mapAsync(writeSettings.parallelism)(doc =>
            session.flatMap(_.upsertDoc(doc, writeSettings))(materializer.system.dispatcher))
      }
      .mapMaterializedValue(_ => NotUsed)

  /**
   * Create a flow to update or insert a Couchbase document of the given class and emit a result so that write failures
   * can be handled in-stream.
   */
  def upsertDocWithResult[T <: Document[_]](sessionSettings: CouchbaseSessionSettings,
      writeSettings: CouchbaseWriteSettings,
      bucketName: String): Flow[T, CouchbaseWriteResult[T], NotUsed] =
    Flow
      .fromMaterializer { (materializer, _) =>
        val session = CouchbaseSessionRegistry(materializer.system).sessionFor(sessionSettings, bucketName)
        Flow[T]
          .mapAsync(writeSettings.parallelism)(doc => {
            implicit val executor: ExecutionContext = materializer.system.dispatcher
            session
              .flatMap(_.upsertDoc(doc, writeSettings))
              .map(_ => CouchbaseWriteSuccess(doc))
              .recover {
                case exception => CouchbaseWriteFailure(doc, exception)
              }
          })
      }
      .mapMaterializedValue(_ => NotUsed)

  /**
   * Create a flow to replace a Couchbase [[com.couchbase.client.java.document.JsonDocument JsonDocument]].
   */
  def replace(sessionSettings: CouchbaseSessionSettings,
      writeSettings: CouchbaseWriteSettings,
      bucketName: String): Flow[JsonDocument, JsonDocument, NotUsed] =
    Flow
      .fromMaterializer { (materializer, _) =>
        val session = CouchbaseSessionRegistry(materializer.system).sessionFor(sessionSettings, bucketName)
        Flow[JsonDocument]
          .mapAsync(writeSettings.parallelism)(doc =>
            session.flatMap(_.replace(doc, writeSettings))(materializer.system.dispatcher))
      }
      .mapMaterializedValue(_ => NotUsed)

  /**
   * Create a flow to replace a Couchbase document of the given class.
   */
  def replaceDoc[T <: Document[_]](sessionSettings: CouchbaseSessionSettings,
      writeSettings: CouchbaseWriteSettings,
      bucketName: String): Flow[T, T, NotUsed] =
    Flow
      .fromMaterializer { (materializer, _) =>
        val session = CouchbaseSessionRegistry(materializer.system).sessionFor(sessionSettings, bucketName)
        Flow[T]
          .mapAsync(writeSettings.parallelism)(doc =>
            session.flatMap(_.replaceDoc(doc, writeSettings))(materializer.system.dispatcher))
      }
      .mapMaterializedValue(_ => NotUsed)

  /**
   * Create a flow to replace a Couchbase document of the given class and emit a result so that write failures
   * can be handled in-stream.
   */
  def replaceDocWithResult[T <: Document[_]](sessionSettings: CouchbaseSessionSettings,
      writeSettings: CouchbaseWriteSettings,
      bucketName: String): Flow[T, CouchbaseWriteResult[T], NotUsed] =
    Flow
      .fromMaterializer { (materializer, _) =>
        val session = CouchbaseSessionRegistry(materializer.system).sessionFor(sessionSettings, bucketName)
        Flow[T]
          .mapAsync(writeSettings.parallelism)(doc => {
            implicit val executor: ExecutionContext = materializer.system.dispatcher
            session
              .flatMap(_.replaceDoc(doc, writeSettings))
              .map(_ => CouchbaseWriteSuccess(doc))
              .recover {
                case exception => CouchbaseWriteFailure(doc, exception)
              }
          })
      }
      .mapMaterializedValue(_ => NotUsed)

  /**
   * Create a flow to delete documents from Couchbase by `id`. Emits the same `id`.
   */
  def delete(sessionSettings: CouchbaseSessionSettings,
      writeSettings: CouchbaseWriteSettings,
      bucketName: String): Flow[String, String, NotUsed] =
    Flow
      .fromMaterializer { (materializer, _) =>
        val session = CouchbaseSessionRegistry(materializer.system).sessionFor(sessionSettings, bucketName)
        Flow[String]
          .mapAsync(writeSettings.parallelism)(id => {
            implicit val executor: ExecutionContext = materializer.system.dispatcher
            session
              .flatMap(_.remove(id, writeSettings))
              .map(_ => id)
          })
      }
      .mapMaterializedValue(_ => NotUsed)

  /**
   * Create a flow to delete documents from Couchbase by `id` and emit operation outcome containing the same `id`.
   */
  def deleteWithResult(sessionSettings: CouchbaseSessionSettings,
      writeSettings: CouchbaseWriteSettings,
      bucketName: String): Flow[String, CouchbaseDeleteResult, NotUsed] =
    Flow
      .fromMaterializer { (materializer, _) =>
        val session = CouchbaseSessionRegistry(materializer.system).sessionFor(sessionSettings, bucketName)
        Flow[String]
          .mapAsync(writeSettings.parallelism)(id => {
            implicit val executor: ExecutionContext = materializer.system.dispatcher
            session
              .flatMap(_.remove(id, writeSettings))
              .map(_ => CouchbaseDeleteSuccess(id))
              .recover {
                case exception => CouchbaseDeleteFailure(id, exception)
              }
          })
      }
      .mapMaterializedValue(_ => NotUsed)
}
