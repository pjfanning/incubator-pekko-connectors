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
import pekko.annotation.InternalApi
import pekko.http.scaladsl.unmarshalling.Unmarshaller
import pdi.jwt.JwtTime
import io.circe._
import io.circe.generic.semiauto._

import java.time.Clock
import scala.concurrent.duration._

@InternalApi
private[auth] final case class AccessToken(token: String, expiresAt: Long) {
  def expiresSoon(in: FiniteDuration = 1.minute)(implicit clock: Clock): Boolean =
    expiresAt < JwtTime.nowSeconds + in.toSeconds
}

@InternalApi
private[auth] object AccessToken {
  implicit def unmarshaller[T](implicit unmarshaller: Unmarshaller[T, AccessTokenResponse],
      clock: Clock): Unmarshaller[T, AccessToken] =
    unmarshaller.map {
      case AccessTokenResponse(access_token, _, expires_in) =>
        AccessToken(access_token, JwtTime.nowSeconds + expires_in)
    }
}

@InternalApi
private[auth] final case class AccessTokenResponse(access_token: String, token_type: String, expires_in: Int)

@InternalApi
private[auth] object AccessTokenResponse {
  implicit val accessTokenResponseDecoder: Decoder[AccessTokenResponse] = deriveDecoder[AccessTokenResponse]
  implicit val accessTokenResponseEncoder: Encoder[AccessTokenResponse] = deriveEncoder[AccessTokenResponse]
}
