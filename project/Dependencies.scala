/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * license agreements; and to You under the Apache License, version 2.0:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * This file is part of the Apache Pekko project, derived from Akka.
 */

import sbt._
import Keys._

object Dependencies {

  val CronBuild = sys.env.get("GITHUB_EVENT_NAME").contains("schedule")

  val Scala213 = "2.13.10" // update even in link-validator.conf
  val Scala212 = "2.12.17"
  val Scala3 = "3.3.0"
  val ScalaVersions = Seq(Scala213, Scala212, Scala3)

  val PekkoVersion = "0.0.0+26669-ec5b6764-SNAPSHOT"
  val PekkoBinaryVersion = "current"

  val InfluxDBJavaVersion = "2.15"

  val AwsSdk2Version = "2.17.113"
  val AwsSpiPekkoHttpVersion = "0.0.11+81-41b69193-SNAPSHOT"
  // Sync with plugins.sbt
  val PekkoGrpcBinaryVersion = "current"
  val PekkoHttpVersion = "0.0.0+4411-6fe04045-SNAPSHOT"
  val PekkoHttpBinaryVersion = "current"
  val ScalaTestVersion = "3.2.11"
  val TestContainersScalaTestVersion = "0.40.14"
  val mockitoVersion = "4.2.0" // check even https://github.com/scalatest/scalatestplus-mockito/releases
  val hoverflyVersion = "0.14.1"
  val scalaCheckVersion = "1.15.4"

  /**
   * Calculates the scalatest version in a format that is used for `org.scalatestplus` scalacheck artifacts
   *
   * @see
   * https://www.scalatest.org/user_guide/property_based_testing
   */
  private def scalaTestPlusScalaCheckVersion(version: String) =
    version.split('.').take(2).mkString("-")

  val scalaTestScalaCheckArtifact = s"scalacheck-${scalaTestPlusScalaCheckVersion(scalaCheckVersion)}"
  val scalaTestScalaCheckVersion = s"$ScalaTestVersion.0"

  val CouchbaseVersion = "2.7.16"
  val CouchbaseVersionForDocs = "2.7"

  val JwtCoreVersion = "3.0.1"

  val log4jOverSlf4jVersion = "1.7.36"
  val jclOverSlf4jVersion = "1.7.36"

  val Common = Seq(
    // These libraries are added to all modules via the `Common` AutoPlugin
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-stream" % PekkoVersion))

  val testkit = Seq(
    libraryDependencies := Seq(
      "org.scala-lang.modules" %% "scala-collection-compat" % "2.10.0",
      "org.apache.pekko" %% "pekko-stream" % PekkoVersion,
      "org.apache.pekko" %% "pekko-stream-testkit" % PekkoVersion,
      "org.apache.pekko" %% "pekko-slf4j" % PekkoVersion,
      "ch.qos.logback" % "logback-classic" % "1.2.11", // Eclipse Public License 1.0
      "org.scalatest" %% "scalatest" % ScalaTestVersion,
      "com.dimafeng" %% "testcontainers-scala-scalatest" % TestContainersScalaTestVersion,
      "com.novocode" % "junit-interface" % "0.11", // BSD-style
      "junit" % "junit" % "4.13" // Eclipse Public License 1.0
    ))

  val Mockito = Seq(
    "org.mockito" % "mockito-core" % mockitoVersion % Test,
    // https://github.com/scalatest/scalatestplus-mockito/releases
    "org.scalatestplus" %% "mockito-4-2" % (ScalaTestVersion + ".0") % Test)

  // Releases https://github.com/FasterXML/jackson-databind/releases
  // CVE issues https://github.com/FasterXML/jackson-databind/issues?utf8=%E2%9C%93&q=+label%3ACVE
  // This should align with the Jackson minor version used in Pekko 1.0.x
  // https://github.com/apache/incubator-pekko/blob/main/project/Dependencies.scala
  val JacksonDatabindVersion = "2.14.3"
  val JacksonDatabindDependencies = Seq(
    "com.fasterxml.jackson.core" % "jackson-core" % JacksonDatabindVersion,
    "com.fasterxml.jackson.core" % "jackson-databind" % JacksonDatabindVersion)

  val Amqp = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "com.rabbitmq" % "amqp-client" % "5.14.2" // APLv2
    ) ++ Mockito)

  val AwsLambda = Seq(
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion, // ApacheV2
      ("com.github.pjfanning" %% "aws-spi-pekko-http" % AwsSpiPekkoHttpVersion).excludeAll( // ApacheV2

        ExclusionRule(organization = "org.apache.pekko")),
      ("software.amazon.awssdk" % "lambda" % AwsSdk2Version).excludeAll( // ApacheV2

        ExclusionRule("software.amazon.awssdk", "apache-client"),
        ExclusionRule("software.amazon.awssdk", "netty-nio-client"))) ++ Mockito)

  val AzureStorageQueue = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "com.microsoft.azure" % "azure-storage" % "8.0.0" // ApacheV2
    ))

  val CassandraVersionInDocs = "4.0"
  val CassandraDriverVersion = "4.15.0"
  val CassandraDriverVersionInDocs = "4.15"

  val Cassandra = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      ("com.datastax.oss" % "java-driver-core" % CassandraDriverVersion)
        .exclude("com.github.spotbugs", "spotbugs-annotations")
        .exclude("org.apache.tinkerpop", "*") // https://github.com/akka/alpakka/issues/2200
        .exclude("com.esri.geometry", "esri-geometry-api"), // https://github.com/akka/alpakka/issues/2225
      "org.apache.pekko" %% "pekko-discovery" % PekkoVersion % Provided))

  val Couchbase = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "com.couchbase.client" % "java-client" % CouchbaseVersion, // ApacheV2
      "io.reactivex" % "rxjava-reactive-streams" % "1.2.1", // ApacheV2
      "org.apache.pekko" %% "pekko-discovery" % PekkoVersion % Provided, // Apache V2
      "com.typesafe.play" %% "play-json" % "2.9.2" % Test, // Apache V2
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion % Test // Apache V2
    ))

  val `Doc-examples` = Seq(
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-slf4j" % PekkoVersion,
      "org.apache.pekko" %% "pekko-stream-testkit" % PekkoVersion % Test,
      "org.apache.pekko" %% "pekko-connectors-kafka" % "0.0.0+1738-07a19b8e-SNAPSHOT" % Test,
      "junit" % "junit" % "4.13.2" % Test, // Eclipse Public License 1.0
      "org.scalatest" %% "scalatest" % "3.2.11" % Test // ApacheV2
    ))

  val DynamoDB = Seq(
    libraryDependencies ++= Seq(
      ("com.github.pjfanning" %% "aws-spi-pekko-http" % AwsSpiPekkoHttpVersion).excludeAll( // ApacheV2

        ExclusionRule(organization = "org.apache.pekko")),
      ("software.amazon.awssdk" % "dynamodb" % AwsSdk2Version).excludeAll( // ApacheV2

        ExclusionRule("software.amazon.awssdk", "apache-client"),
        ExclusionRule("software.amazon.awssdk", "netty-nio-client")),
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion // ApacheV2
    ))

  val Elasticsearch = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion,
      "org.apache.pekko" %% "pekko-http-spray-json" % PekkoHttpVersion,
      "org.slf4j" % "jcl-over-slf4j" % jclOverSlf4jVersion % Test) ++ JacksonDatabindDependencies)

  val File = Seq(
    libraryDependencies ++= Seq(
      "com.google.jimfs" % "jimfs" % "1.2" % Test // ApacheV2
    ))

  val AvroParquet = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "org.apache.parquet" % "parquet-avro" % "1.10.1", // Apache2
      ("org.apache.hadoop" % "hadoop-client" % "3.2.1" % Test).exclude("log4j", "log4j"), // Apache2
      ("org.apache.hadoop" % "hadoop-common" % "3.2.1" % Test).exclude("log4j", "log4j"), // Apache2
      "com.sksamuel.avro4s" %% "avro4s-core" % "4.1.1" % Test,
      "org.scalacheck" %% "scalacheck" % scalaCheckVersion % Test,
      "org.specs2" %% "specs2-core" % "4.20.0" % Test, // MIT like: https://github.com/etorreborre/specs2/blob/master/LICENSE.txt
      "org.slf4j" % "log4j-over-slf4j" % log4jOverSlf4jVersion % Test // MIT like: http://www.slf4j.org/license.html
    ))

  val Ftp = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "commons-net" % "commons-net" % "3.8.0", // ApacheV2
      "com.hierynomus" % "sshj" % "0.33.0" // ApacheV2
    ))

  val GeodeVersion = "1.15.0"
  val GeodeVersionForDocs = "115"

  val Geode = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++=
      Seq("geode-core", "geode-cq")
        .map("org.apache.geode" % _ % GeodeVersion) ++
      Seq(
        "com.chuusai" %% "shapeless" % "2.3.3",
        "org.apache.logging.log4j" % "log4j-to-slf4j" % "2.17.1" % Test) ++ JacksonDatabindDependencies)

  val GoogleCommon = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion,
      "org.apache.pekko" %% "pekko-http-spray-json" % PekkoHttpVersion,
      "com.github.jwt-scala" %% "jwt-spray-json" % "7.1.4", // ApacheV2
      "com.google.auth" % "google-auth-library-credentials" % "0.24.1", // BSD 3-clause
      "io.specto" % "hoverfly-java" % hoverflyVersion % Test // ApacheV2
    ) ++ Mockito)

  val GoogleBigQuery = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion,
      "org.apache.pekko" %% "pekko-http-jackson" % PekkoHttpVersion % Provided,
      "org.apache.pekko" %% "pekko-http-spray-json" % PekkoHttpVersion,
      "io.spray" %% "spray-json" % "1.3.6",
      "com.fasterxml.jackson.core" % "jackson-annotations" % JacksonDatabindVersion,
      "com.fasterxml.jackson.datatype" % "jackson-datatype-jsr310" % JacksonDatabindVersion % Test,
      "io.specto" % "hoverfly-java" % hoverflyVersion % Test // ApacheV2
    ) ++ Mockito)
  val GoogleBigQueryStorage = Seq(
    crossScalaVersions -= Scala3,
    // see Pekko gRPC version in plugins.sbt
    libraryDependencies ++= Seq(
      // https://github.com/googleapis/java-bigquerystorage/tree/master/proto-google-cloud-bigquerystorage-v1
      "com.google.api.grpc" % "proto-google-cloud-bigquerystorage-v1" % "1.22.0" % "protobuf-src", // ApacheV2
      "org.apache.avro" % "avro" % "1.9.2" % "provided",
      "org.apache.arrow" % "arrow-vector" % "4.0.0" % "provided",
      "io.grpc" % "grpc-auth" % org.apache.pekko.grpc.gen.BuildInfo.grpcVersion, // ApacheV2
      "org.apache.pekko" %% "pekko-http-spray-json" % PekkoHttpVersion,
      "org.apache.pekko" %% "pekko-http-core" % PekkoHttpVersion,
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion,
      "org.apache.pekko" %% "pekko-parsing" % PekkoHttpVersion,
      "org.apache.arrow" % "arrow-memory-netty" % "4.0.1" % Test,
      "org.apache.pekko" %% "pekko-discovery" % PekkoVersion) ++ Mockito)

  val GooglePubSub = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion,
      "org.apache.pekko" %% "pekko-http-spray-json" % PekkoHttpVersion,
      "com.github.tomakehurst" % "wiremock" % "2.27.2" % Test // ApacheV2
    ) ++ Mockito)

  val GooglePubSubGrpc = Seq(
    crossScalaVersions -= Scala3,
    // see Pekko gRPC version in plugins.sbt
    libraryDependencies ++= Seq(
      // https://github.com/googleapis/java-pubsub/tree/master/proto-google-cloud-pubsub-v1/
      "com.google.cloud" % "google-cloud-pubsub" % "1.112.5" % "protobuf-src", // ApacheV2
      "io.grpc" % "grpc-auth" % org.apache.pekko.grpc.gen.BuildInfo.grpcVersion, // ApacheV2
      "com.google.auth" % "google-auth-library-oauth2-http" % "0.22.2", // BSD 3-clause
      // pull in Pekko Discovery for our Pekko version
      "org.apache.pekko" %% "pekko-discovery" % PekkoVersion))

  val GoogleFcm = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion,
      "org.apache.pekko" %% "pekko-http-spray-json" % PekkoHttpVersion) ++ Mockito)

  val GoogleStorage = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion,
      "org.apache.pekko" %% "pekko-http-spray-json" % PekkoHttpVersion,
      "io.specto" % "hoverfly-java" % hoverflyVersion % Test // ApacheV2
    ) ++ Mockito)

  val HBase = {
    val hbaseVersion = "1.4.13"
    val hadoopVersion = "2.7.7"
    Seq(
      libraryDependencies ++= Seq(
        ("org.apache.hbase" % "hbase-shaded-client" % hbaseVersion).exclude("log4j", "log4j").exclude("org.slf4j",
          "slf4j-log4j12"), // ApacheV2,
        ("org.apache.hbase" % "hbase-common" % hbaseVersion).exclude("log4j", "log4j").exclude("org.slf4j",
          "slf4j-log4j12"), // ApacheV2,
        ("org.apache.hadoop" % "hadoop-common" % hadoopVersion).exclude("log4j", "log4j").exclude("org.slf4j",
          "slf4j-log4j12"), // ApacheV2,
        ("org.apache.hadoop" % "hadoop-mapreduce-client-core" % hadoopVersion).exclude("log4j", "log4j").exclude(
          "org.slf4j", "slf4j-log4j12"), // ApacheV2,
        "org.slf4j" % "log4j-over-slf4j" % log4jOverSlf4jVersion % Test // MIT like: http://www.slf4j.org/license.html
      ))
  }

  val HadoopVersion = "3.2.1"
  val Hdfs = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      ("org.apache.hadoop" % "hadoop-client" % HadoopVersion).exclude("log4j", "log4j").exclude("org.slf4j",
        "slf4j-log4j12"), // ApacheV2
      "org.typelevel" %% "cats-core" % "2.0.0", // MIT,
      ("org.apache.hadoop" % "hadoop-hdfs" % HadoopVersion % Test).exclude("log4j", "log4j").exclude("org.slf4j",
        "slf4j-log4j12"), // ApacheV2
      ("org.apache.hadoop" % "hadoop-common" % HadoopVersion % Test).exclude("log4j", "log4j").exclude("org.slf4j",
        "slf4j-log4j12"), // ApacheV2
      ("org.apache.hadoop" % "hadoop-minicluster" % HadoopVersion % Test).exclude("log4j", "log4j").exclude("org.slf4j",
        "slf4j-log4j12"), // ApacheV2
      "org.slf4j" % "log4j-over-slf4j" % log4jOverSlf4jVersion % Test // MIT like: http://www.slf4j.org/license.html
    ))

  val HuaweiPushKit = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion,
      "org.apache.pekko" %% "pekko-http-spray-json" % PekkoHttpVersion,
      "com.github.jwt-scala" %% "jwt-spray-json" % "7.1.4" // ApacheV2
    ) ++ Mockito)

  val InfluxDB = Seq(
    libraryDependencies ++= Seq(
      "org.influxdb" % "influxdb-java" % InfluxDBJavaVersion // MIT
    ))

  val IronMq = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion,
      "com.github.pjfanning" %% "pekko-http-circe" % "1.40.0-RC3_23-bb29e2a9-SNAPSHOT" // ApacheV2
    ))

  val Jms = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "javax.jms" % "jms" % "1.1" % Provided, // CDDL + GPLv2
      "com.ibm.mq" % "com.ibm.mq.allclient" % "9.2.5.0" % Test, // IBM International Program License Agreement https://public.dhe.ibm.com/ibmdl/export/pub/software/websphere/messaging/mqdev/maven/licenses/L-APIG-AZYF2E/LI_en.html
      "org.apache.activemq" % "activemq-broker" % "5.16.4" % Test, // ApacheV2
      "org.apache.activemq" % "activemq-client" % "5.16.4" % Test, // ApacheV2
      "io.github.sullis" %% "jms-testkit" % "1.0.4" % Test // ApacheV2
    ) ++ Mockito,
    // Having JBoss as a first resolver is a workaround for https://github.com/coursier/coursier/issues/200
    externalResolvers := ("jboss".at(
      "https://repository.jboss.org/nexus/content/groups/public")) +: externalResolvers.value)

  val JsonStreaming = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "com.github.jsurfer" % "jsurfer-jackson" % "1.6.0" // MIT
    ) ++ JacksonDatabindDependencies)

  val Kinesis = Seq(
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion, // ApacheV2
      ("com.github.pjfanning" %% "aws-spi-pekko-http" % AwsSpiPekkoHttpVersion).excludeAll(ExclusionRule(
        organization = "org.apache.pekko"))) ++ Seq(
      "software.amazon.awssdk" % "kinesis" % AwsSdk2Version, // ApacheV2
      "software.amazon.awssdk" % "firehose" % AwsSdk2Version, // ApacheV2
      "software.amazon.kinesis" % "amazon-kinesis-client" % "2.4.0" // ApacheV2
    ).map(
      _.excludeAll(
        ExclusionRule("software.amazon.awssdk", "apache-client"),
        ExclusionRule("software.amazon.awssdk", "netty-nio-client"))) ++ Mockito)

  val KuduVersion = "1.7.1"
  val Kudu = Seq(
    libraryDependencies ++= Seq(
      "org.apache.kudu" % "kudu-client-tools" % KuduVersion, // ApacheV2
      "org.apache.kudu" % "kudu-client" % KuduVersion % Test // ApacheV2
    ))

  val MongoDb = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "org.mongodb.scala" %% "mongo-scala-driver" % "4.4.0" // ApacheV2
    ))

  val Mqtt = Seq(
    libraryDependencies ++= Seq(
      "org.eclipse.paho" % "org.eclipse.paho.client.mqttv3" % "1.2.5" // Eclipse Public License 1.0
    ))

  val MqttStreaming = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-actor-typed" % PekkoVersion, // ApacheV2
      "org.apache.pekko" %% "pekko-actor-testkit-typed" % PekkoVersion % Test, // ApacheV2
      "org.apache.pekko" %% "pekko-stream-typed" % PekkoVersion, // ApacheV2
      "org.apache.pekko" %% "pekko-stream-testkit" % PekkoVersion % Test // ApacheV2
    ))

  val OrientDB = Seq(
    libraryDependencies ++= Seq(
      ("com.orientechnologies" % "orientdb-graphdb" % "3.1.9")
        .exclude("com.tinkerpop.blueprints", "blueprints-core"),
      "com.orientechnologies" % "orientdb-object" % "3.1.9" // ApacheV2
    ))

  val PravegaVersion = "0.10.2"
  val PravegaVersionForDocs = s"v$PravegaVersion"

  val Pravega = {
    Seq(
      libraryDependencies ++= Seq(
        "io.pravega" % "pravega-client" % PravegaVersion,
        "org.slf4j" % "log4j-over-slf4j" % log4jOverSlf4jVersion % Test // MIT like: http://www.slf4j.org/license.html
      ))
  }

  val Reference = Seq(
    // connector specific library dependencies and resolver settings
    libraryDependencies ++= Seq(
    ))

  val S3 = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion,
      "org.apache.pekko" %% "pekko-http-xml" % PekkoHttpVersion,
      "software.amazon.awssdk" % "auth" % AwsSdk2Version,
      // in-memory filesystem for file related tests
      "com.google.jimfs" % "jimfs" % "1.2" % Test, // ApacheV2
      "com.github.tomakehurst" % "wiremock-jre8" % "2.32.0" % Test, // ApacheV2
      "org.scalacheck" %% "scalacheck" % scalaCheckVersion % Test,
      "org.scalatestplus" %% scalaTestScalaCheckArtifact % scalaTestScalaCheckVersion % Test,
      "com.markatta" %% "futiles" % "2.0.2" % Test))

  val SpringWeb = {
    val SpringVersion = "5.1.17.RELEASE"
    val SpringBootVersion = "2.1.16.RELEASE"
    Seq(
      libraryDependencies ++= Seq(
        "org.springframework" % "spring-core" % SpringVersion,
        "org.springframework" % "spring-context" % SpringVersion,
        "org.springframework.boot" % "spring-boot-autoconfigure" % SpringBootVersion, // TODO should this be provided?
        "org.springframework.boot" % "spring-boot-configuration-processor" % SpringBootVersion % Optional,
        // for examples
        "org.springframework.boot" % "spring-boot-starter-web" % SpringBootVersion % Test))
  }

  val SlickVersion = "3.3.3"
  val Slick = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "com.typesafe.slick" %% "slick" % SlickVersion, // BSD 2-clause "Simplified" License
      "com.typesafe.slick" %% "slick-hikaricp" % SlickVersion, // BSD 2-clause "Simplified" License
      "com.h2database" % "h2" % "2.1.210" % Test // Eclipse Public License 1.0
    ))
  val Eventbridge = Seq(
    libraryDependencies ++= Seq(
      ("com.github.pjfanning" %% "aws-spi-pekko-http" % AwsSpiPekkoHttpVersion).excludeAll( // ApacheV2

        ExclusionRule(organization = "org.apache.pekko")),
      ("software.amazon.awssdk" % "eventbridge" % AwsSdk2Version).excludeAll( // ApacheV2

        ExclusionRule("software.amazon.awssdk", "apache-client"),
        ExclusionRule("software.amazon.awssdk", "netty-nio-client")),
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion // ApacheV2
    ) ++ Mockito)

  val Sns = Seq(
    libraryDependencies ++= Seq(
      ("com.github.pjfanning" %% "aws-spi-pekko-http" % AwsSpiPekkoHttpVersion).excludeAll( // ApacheV2

        ExclusionRule(organization = "org.apache.pekko")),
      ("software.amazon.awssdk" % "sns" % AwsSdk2Version).excludeAll( // ApacheV2

        ExclusionRule("software.amazon.awssdk", "apache-client"),
        ExclusionRule("software.amazon.awssdk", "netty-nio-client")),
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion // ApacheV2
    ) ++ Mockito)

  val SolrjVersion = "7.7.3"
  val SolrVersionForDocs = "7_7"

  val Solr = Seq(
    libraryDependencies ++= Seq(
      "org.apache.solr" % "solr-solrj" % SolrjVersion, // ApacheV2
      ("org.apache.solr" % "solr-test-framework" % SolrjVersion % Test).exclude("org.apache.logging.log4j",
        "log4j-slf4j-impl"), // ApacheV2
      "org.slf4j" % "log4j-over-slf4j" % log4jOverSlf4jVersion % Test // MIT like: http://www.slf4j.org/license.html
    ),
    resolvers += ("restlet".at("https://maven.restlet.talend.com")))

  val Sqs = Seq(
    libraryDependencies ++= Seq(
      ("com.github.pjfanning" %% "aws-spi-pekko-http" % AwsSpiPekkoHttpVersion).excludeAll( // ApacheV2

        ExclusionRule(organization = "org.apache.pekko")),
      ("software.amazon.awssdk" % "sqs" % AwsSdk2Version).excludeAll( // ApacheV2

        ExclusionRule("software.amazon.awssdk", "apache-client"),
        ExclusionRule("software.amazon.awssdk", "netty-nio-client")),
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion, // ApacheV2
      "org.mockito" % "mockito-inline" % mockitoVersion % Test // MIT
    ) ++ Mockito)

  val Sse = Seq(
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-http" % PekkoHttpVersion,
      "org.apache.pekko" %% "pekko-http-testkit" % PekkoHttpVersion % Test))

  val UnixDomainSocket = Seq(
    crossScalaVersions -= Scala3,
    libraryDependencies ++= Seq(
      "com.github.jnr" % "jffi" % "1.3.1", // classifier "complete", // Is the classifier needed anymore?
      "com.github.jnr" % "jnr-unixsocket" % "0.38.5" // BSD/ApacheV2/CPL/MIT as per https://github.com/akka/alpakka/issues/620#issuecomment-348727265
    ))

  val Xml = Seq(
    libraryDependencies ++= Seq(
      "com.fasterxml" % "aalto-xml" % "1.2.2" // ApacheV2
    ))

}
