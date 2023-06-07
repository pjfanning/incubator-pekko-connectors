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

package org.apache.pekko.stream.connectors.google.auth

import org.apache.pekko
import pekko.http.scaladsl.model.{ ErrorInfo, ExceptionWithErrorInfo, HttpResponse }
import pekko.http.scaladsl.unmarshalling.{ FromResponseUnmarshaller, PredefinedFromEntityUnmarshallers, Unmarshaller }
import pekko.stream.connectors.google.implicits._
import pekko.stream.connectors.google.util.Retry

import io.circe._
import io.circe.generic.semiauto._

final case class GoogleOAuth2Exception private (override val info: ErrorInfo) extends ExceptionWithErrorInfo(info)

private[google] object GoogleOAuth2Exception {

  private val internalFailure = "internal_failure"
  private final case class OAuth2ErrorResponse(error: Option[String], error_description: Option[String])
  private implicit val oAuth2ErrorResponseDecoder: Decoder[OAuth2ErrorResponse] = deriveDecoder[OAuth2ErrorResponse]
  private implicit val oAuth2ErrorResponseEncoder: Encoder[OAuth2ErrorResponse] = deriveEncoder[OAuth2ErrorResponse]

  import com.github.pjfanning.pekkohttpcirce.FailFastCirceSupport._
  implicit val unmarshaller: FromResponseUnmarshaller[Throwable] =
    Unmarshaller
      .identityUnmarshaller[HttpResponse]
      .map(_.entity)
      .andThen(
        Unmarshaller.firstOf(
          unmarshaller[OAuth2ErrorResponse],
          PredefinedFromEntityUnmarshallers.stringUnmarshaller.map(s => OAuth2ErrorResponse(None, Some(s)))))
      .mapWithInput {
        case (response, OAuth2ErrorResponse(error, error_description)) =>
          val ex = GoogleOAuth2Exception(
            ErrorInfo(error.getOrElse(response.status.value),
              error_description.getOrElse(response.status.defaultMessage)))
          // https://github.com/googleapis/google-auth-library-python/blob/master/google/oauth2/_client.py
          if (ex.info.summary == internalFailure || ex.info.detail == internalFailure)
            Retry(ex): Throwable
          else
            ex
      }
      .withDefaultRetry
}
