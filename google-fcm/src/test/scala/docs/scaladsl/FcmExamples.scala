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

package docs.scaladsl

//#imports
import org.apache.pekko
import pekko.actor.ActorSystem
import pekko.stream.connectors.google.firebase.fcm.FcmSettings
import pekko.stream.connectors.google.firebase.fcm.v1.models._
import pekko.stream.connectors.google.firebase.fcm.v1.scaladsl.GoogleFcm

//#imports
import pekko.stream.scaladsl.{ Sink, Source }

import scala.collection.immutable
import scala.concurrent.Future

class FcmExamples {

  implicit val system: ActorSystem = ActorSystem()

  // #simple-send
  val fcmConfig = FcmSettings()
  val notification = FcmNotification("Test", "This is a test notification!", Token("token"))
  Source
    .single(notification)
    .runWith(GoogleFcm.fireAndForget(fcmConfig))
  // #simple-send

  // #asFlow-send
  val result1: Future[immutable.Seq[FcmResponse]] =
    Source
      .single(notification)
      .via(GoogleFcm.send(fcmConfig))
      .map {
        case res @ FcmSuccessResponse(name) =>
          println(s"Successful $name")
          res
        case res @ FcmErrorResponse(errorMessage) =>
          println(s"Send error $errorMessage")
          res
      }
      .runWith(Sink.seq)
  // #asFlow-send

  // #withData-send
  val result2: Future[immutable.Seq[(FcmResponse, String)]] =
    Source
      .single((notification, "superData"))
      .via(GoogleFcm.sendWithPassThrough(fcmConfig))
      .runWith(Sink.seq)
  // #withData-send

  // #noti-create
  val buildedNotification = FcmNotification.empty
    .withTarget(Topic("testers"))
    .withBasicNotification("title", "body")
    // .withAndroidConfig(AndroidConfig(...))
    // .withApnsConfig(ApnsConfig(...))
    .withWebPushConfig(
      WebPushConfig(
        headers = Option(Map.empty),
        data = Option(Map.empty),
        notification =
          Option("{\"title\": \"web-title\", \"body\": \"web-body\", \"icon\": \"http://example.com/icon.png\"}")))
  val sendable = buildedNotification.isSendable
  // #noti-create

  // #condition-builder
  import Condition.{ Topic => CTopic }
  val condition = Condition(CTopic("TopicA") && (CTopic("TopicB") || (CTopic("TopicC") && !CTopic("TopicD"))))
  val conditioneddNotification = FcmNotification("Test", "This is a test notification!", condition)
  // #condition-builder

}
