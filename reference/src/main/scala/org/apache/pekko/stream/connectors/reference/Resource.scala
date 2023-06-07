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

package org.apache.pekko.stream.connectors.reference

import org.apache.pekko
import pekko.actor.{
  ActorSystem,
  ClassicActorSystemProvider,
  ExtendedActorSystem,
  Extension,
  ExtensionId,
  ExtensionIdProvider
}
import pekko.stream.scaladsl.Flow
import pekko.util.ByteString
import com.typesafe.config.Config

/**
 * Some connectors might require an external resource that is used in the
 * Source, Flow and/or Sink factories.
 *
 * For example dynamodb connector needs a DynamoClient to create Sources and Flows.
 * Another example is Google Pub Sub gRPC connector that uses Grpc Publishers and
 * Subscribers to create Sources and Sinks. Another connector, Pekko Connectors Kafka, uses
 * an actor that can be shared across different streams.
 *
 * If your connector uses such a resource and it is possible to reuse that resource
 * across different Pekko Stream operator factories, put that resource to a separate
 * class like below.
 */
final class Resource private (val settings: ResourceSettings) {
  // a resource that is to be used when creating Pekko Stream operators.
  val connection = Flow[ByteString].map(_.reverse)

  /**
   * Resource cleanup logic
   */
  def cleanup() = {}
}

object Resource {
  def apply(settings: ResourceSettings) = new Resource(settings)

  def create(settings: ResourceSettings) = Resource(settings)
}

/**
 * Settings required for the Resource should be extracted to a separate class.
 */
final class ResourceSettings private (val msg: String) {
  override def toString: String =
    s"ResourceSettings(msg=$msg)"
}

/**
 * Factories for the settings object should take parameters as well as a `Config`
 * instance for reading values from HOCON.
 */
object ResourceSettings {
  val ConfigPath = "pekko.connectors.reference"

  def apply(msg: String): ResourceSettings = new ResourceSettings(msg)

  /**
   * Java Api
   */
  def create(msg: String): ResourceSettings = ResourceSettings(msg)

  /**
   * Resolves settings from a given Config object, which should have all of the required
   * values at the top level.
   */
  def apply(config: Config): ResourceSettings = {
    val msg = config.getString("msg")
    ResourceSettings(msg)
  }

  /**
   * Java Api
   *
   * Resolves settings from a given Config object, which should have all of the required
   * values at the top level.
   */
  def create(config: Config): ResourceSettings =
    ResourceSettings(config)

  /**
   * Resolves settings from the `ActorSystem`s settings.
   */
  def apply()(implicit sys: ClassicActorSystemProvider): ResourceSettings =
    ResourceSettings(sys.classicSystem.settings.config.getConfig(ConfigPath))

  /**
   * Java Api
   *
   * Resolves settings from the `ActorSystem`s settings.
   */
  def create(sys: ClassicActorSystemProvider): ResourceSettings =
    ResourceSettings()(sys)
}

/**
 * In order to minimise the user facing API, the resource lifetime can be managed by an
 * Pekko Extension. In that case Pekko Extension will make sure that
 * there is only one instance of the resource instantiated per Actor System.
 */
final class ResourceExt private (sys: ExtendedActorSystem) extends Extension {
  implicit val resource: Resource = Resource(ResourceSettings()(sys))

  sys.registerOnTermination(resource.cleanup())
}

object ResourceExt extends ExtensionId[ResourceExt] with ExtensionIdProvider {
  override def lookup = ResourceExt
  override def createExtension(system: ExtendedActorSystem) = new ResourceExt(system)

  /**
   * Access to extension.
   */
  def apply()(implicit system: ClassicActorSystemProvider): ResourceExt = super.apply(system)

  /**
   * Access to extension.
   * Java API.
   */
  override def get(system: ActorSystem): ResourceExt = super.get(system)

  /**
   * Access to extension.
   * Java API.
   */
  override def get(system: ClassicActorSystemProvider): ResourceExt = super.get(system)
}
