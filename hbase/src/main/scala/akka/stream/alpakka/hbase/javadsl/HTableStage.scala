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

package akka.stream.alpakka.hbase.javadsl

import java.util.concurrent.CompletionStage

import akka.stream.alpakka.hbase.HTableSettings
import akka.stream.alpakka.hbase.impl.{ HBaseFlowStage, HBaseSourceStage }
import akka.stream.scaladsl.{ Flow, Keep, Sink, Source }
import akka.{ Done, NotUsed }
import org.apache.hadoop.hbase.client.{ Result, Scan }

import scala.compat.java8.FutureConverters._

object HTableStage {

  /**
   * Writes incoming element to HBase.
   * HBase mutations for every incoming element are derived from the converter functions defined in the config.
   */
  def sink[A](config: HTableSettings[A]): akka.stream.javadsl.Sink[A, CompletionStage[Done]] =
    Flow[A].via(flow(config)).toMat(Sink.ignore)(Keep.right).mapMaterializedValue(toJava).asJava

  /**
   * Writes incoming element to HBase.
   * HBase mutations for every incoming element are derived from the converter functions defined in the config.
   */
  def flow[A](settings: HTableSettings[A]): akka.stream.javadsl.Flow[A, A, NotUsed] =
    Flow.fromGraph(new HBaseFlowStage[A](settings)).asJava

  /**
   * Reads an element from HBase.
   */
  def source[A](scan: Scan, settings: HTableSettings[A]): akka.stream.javadsl.Source[Result, NotUsed] =
    Source.fromGraph(new HBaseSourceStage[A](scan, settings)).asJava

}
