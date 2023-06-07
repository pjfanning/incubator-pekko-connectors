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

package org.apache.pekko.stream.connectors.hbase.impl

import org.apache.pekko
import pekko.stream.{ Attributes, Outlet, SourceShape }
import pekko.stream.connectors.hbase.HTableSettings
import pekko.stream.stage.{ GraphStage, GraphStageLogic, OutHandler, StageLogging }
import org.apache.hadoop.hbase.client.{ Connection, Result, Scan, Table }

import scala.util.control.NonFatal

private[hbase] final class HBaseSourceStage[A](scan: Scan, settings: HTableSettings[A])
    extends GraphStage[SourceShape[Result]] {

  val out: Outlet[Result] = Outlet("HBaseSource.out")
  override val shape: SourceShape[Result] = SourceShape(out)

  override def createLogic(inheritedAttributes: Attributes): GraphStageLogic =
    new HBaseSourceLogic[A](scan, settings, out, shape)
}

private[hbase] final class HBaseSourceLogic[A](scan: Scan,
    settings: HTableSettings[A],
    out: Outlet[Result],
    shape: SourceShape[Result])
    extends GraphStageLogic(shape)
    with OutHandler
    with StageLogging
    with HBaseCapabilities {

  implicit val connection: Connection = connect(settings.conf)

  lazy val table: Table = getOrCreateTable(settings.tableName, settings.columnFamilies).get
  private var results: java.util.Iterator[Result] = null

  setHandler(out, this)

  override def preStart(): Unit =
    try {
      val scanner = table.getScanner(scan)
      results = scanner.iterator()
    } catch {
      case NonFatal(exc) =>
        failStage(exc)
    }

  override def postStop(): Unit =
    try {
      table.close()
    } catch {
      case NonFatal(exc) =>
        failStage(exc)
    }

  override def onPull(): Unit =
    if (results.hasNext) {
      emit(out, results.next)
    } else {
      completeStage()
    }

}
