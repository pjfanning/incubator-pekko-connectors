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

package org.apache.pekko.stream.connectors.google

import org.apache.pekko
import pekko.actor.ActorSystem
import pekko.http.scaladsl.marshallers.sprayjson.SprayJsonSupport._
import pekko.http.scaladsl.model.HttpMethods.GET
import pekko.http.scaladsl.model.HttpRequest
import pekko.stream.connectors.google.scaladsl.Paginated
import pekko.stream.scaladsl.Sink
import pekko.testkit.TestKit
import io.specto.hoverfly.junit.core.SimulationSource.dsl
import io.specto.hoverfly.junit.dsl.HoverflyDsl.service
import io.specto.hoverfly.junit.dsl.ResponseCreators.success
import org.scalatest.BeforeAndAfterAll
import org.scalatest.concurrent.ScalaFutures
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpecLike
import spray.json.{ JsObject, JsString, JsValue }

class PaginatedRequestSpec
    extends TestKit(ActorSystem("PaginatedRequestSpec"))
    with AnyWordSpecLike
    with Matchers
    with BeforeAndAfterAll
    with ScalaFutures
    with HoverflySupport {

  override def afterAll(): Unit = {
    TestKit.shutdownActorSystem(system)
    super.afterAll()
  }

  implicit val patience: PatienceConfig = PatienceConfig(remainingOrDefault)
  implicit val paginated: Paginated[JsValue] = _.asJsObject.fields.get("pageToken").flatMap {
    case JsString(value) => Some(value)
    case _               => None
  }

  "PaginatedRequest" should {

    "return single page request" in {

      hoverfly.simulate(
        dsl(
          service("example.com")
            .get("/")
            .queryParam("prettyPrint", "false")
            .header("Authorization", "Bearer yyyy.c.an-access-token")
            .willReturn(success("{}", "application/json"))))

      val result = PaginatedRequest[JsValue](HttpRequest(GET, "https://example.com")).runWith(Sink.head)

      result.futureValue shouldBe JsObject.empty
      hoverfly.reset()
    }

    "return two page request" in {

      hoverfly.simulate(
        dsl(
          service("example.com")
            .get("/")
            .queryParam("prettyPrint", "false")
            .header("Authorization", "Bearer yyyy.c.an-access-token")
            .willReturn(
              success("""{ "pageToken": "nextPage" }""", "application/json"))
            .get("/")
            .queryParam("pageToken", "nextPage")
            .queryParam("prettyPrint", "false")
            .header("Authorization", "Bearer yyyy.c.an-access-token")
            .willReturn(success("{}", "application/json"))))

      val result = PaginatedRequest[JsValue](HttpRequest(GET, "https://example.com")).runWith(Sink.seq)

      result.futureValue shouldBe Seq(JsObject("pageToken" -> JsString("nextPage")), JsObject.empty)
      hoverfly.reset()
    }

    "url encode page token" in {

      hoverfly.simulate(
        dsl(
          service("example.com")
            .get("/")
            .queryParam("prettyPrint", "false")
            .header("Authorization", "Bearer yyyy.c.an-access-token")
            .willReturn(
              success("""{ "pageToken": "===" }""", "application/json"))
            .get("/")
            .queryParam("pageToken", "===")
            .queryParam("prettyPrint", "false")
            .header("Authorization", "Bearer yyyy.c.an-access-token")
            .willReturn(success("{}", "application/json"))))

      val result = PaginatedRequest[JsValue](HttpRequest(GET, "https://example.com")).runWith(Sink.seq)

      result.futureValue shouldBe Seq(JsObject("pageToken" -> JsString("===")), JsObject.empty)
      hoverfly.reset()
    }
  }

}
