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

import java.net.URI

import org.apache.pekko
import pekko.NotUsed
import pekko.actor.ActorSystem
import pekko.stream.connectors.testkit.scaladsl.LogCapturing
import pekko.stream.scaladsl.{ FlowWithContext, SourceWithContext }

import scala.util.{ Failure, Success, Try }
//#init-client

//#init-client
import pekko.stream.connectors.dynamodb.DynamoDbOp._
import pekko.stream.connectors.dynamodb.scaladsl._
import pekko.stream.scaladsl.{ Sink, Source }
import pekko.testkit.TestKit
import org.scalatest.concurrent.ScalaFutures
import org.scalatest.BeforeAndAfterAll
//#init-client
import com.github.pjfanning.pekkohttpspi.PekkoHttpClient
import software.amazon.awssdk.auth.credentials.{ AwsBasicCredentials, StaticCredentialsProvider }
import software.amazon.awssdk.regions.Region
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient

//#init-client
import software.amazon.awssdk.services.dynamodb.model._

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future
import scala.concurrent.duration._
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpecLike

class ExampleSpec
    extends TestKit(ActorSystem("ExampleSpec"))
    with AnyWordSpecLike
    with Matchers
    with BeforeAndAfterAll
    with ScalaFutures
    with LogCapturing {

  override implicit val patienceConfig: PatienceConfig = PatienceConfig(5.seconds, 100.millis)

  // #init-client

  // Don't encode credentials in your source code!
  // see https://pekko.apache.org/docs/pekko-connectors/current/aws-shared-configuration.html
  private val credentialsProvider = StaticCredentialsProvider.create(AwsBasicCredentials.create("x", "x"))
  implicit val client: DynamoDbAsyncClient = DynamoDbAsyncClient
    .builder()
    .region(Region.AWS_GLOBAL)
    .credentialsProvider(credentialsProvider)
    .httpClient(PekkoHttpClient.builder().withActorSystem(system).build())
    // Possibility to configure the retry policy
    // see https://pekko.apache.org/docs/pekko-connectors/current/aws-shared-configuration.html
    // .overrideConfiguration(...)
    // #init-client
    .endpointOverride(new URI("http://localhost:8001/"))
    // #init-client
    .build()

  system.registerOnTermination(client.close())

  // #init-client

  override def afterAll(): Unit = {
    client.close()
    shutdown()
    super.afterAll()
  }

  "DynamoDB" should {

    "provide a simple usage example" in {

      // #simple-request
      val listTablesResult: Future[ListTablesResponse] =
        DynamoDb.single(ListTablesRequest.builder().build())
      // #simple-request

      listTablesResult.futureValue
    }

    "allow multiple requests" in {
      // #flow
      val source: Source[DescribeTableResponse, NotUsed] = Source
        .single(CreateTableRequest.builder().tableName("testTable").build())
        .via(DynamoDb.flow(parallelism = 1))
        .map(response => DescribeTableRequest.builder().tableName(response.tableDescription.tableName).build())
        .via(DynamoDb.flow(parallelism = 1))

      // #flow
      source.runWith(Sink.ignore).failed.futureValue
    }

    "flow with context" in {
      case class SomeContext()

      // #withContext
      val source: SourceWithContext[PutItemRequest, SomeContext, NotUsed] = // ???
        // #withContext
        SourceWithContext.fromTuples(
          Source.single(PutItemRequest.builder().build() -> SomeContext()))

      // #withContext

      val flow: FlowWithContext[PutItemRequest, SomeContext, Try[PutItemResponse], SomeContext, NotUsed] =
        DynamoDb.flowWithContext(parallelism = 1)

      val writtenSource: SourceWithContext[PutItemResponse, SomeContext, NotUsed] = source
        .via(flow)
        .map {
          case Success(response)  => response
          case Failure(exception) => throw exception
        }
      // #withContext

      writtenSource.runWith(Sink.ignore).failed.futureValue
    }

    "allow multiple requests - single source" in {
      (for {
        create <- DynamoDb.single(CreateTableRequest.builder().tableName("testTable").build())
        describe <- DynamoDb.single(
          DescribeTableRequest.builder().tableName(create.tableDescription.tableName).build())
      } yield describe.table.itemCount).failed.futureValue
    }

    "provide a paginated requests source" in {
      // #paginated
      val scanRequest = ScanRequest.builder().tableName("testTable").build()

      val scanPages: Source[ScanResponse, NotUsed] =
        DynamoDb.source(scanRequest)

      // #paginated
      scanPages.runWith(Sink.ignore).failed.futureValue
    }

    "provide a paginated flow" in {
      val scanRequest = ScanRequest.builder().tableName("testTable").build()
      // #paginated
      val scanPageInFlow: Source[ScanResponse, NotUsed] =
        Source
          .single(scanRequest)
          .via(DynamoDb.flowPaginated())
      // #paginated
      scanPageInFlow.runWith(Sink.ignore).failed.futureValue
    }
  }
}
