/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.pekko.stream.connectors.ftp.impl;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.time.Duration;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.commons.net.ftp.*;
import org.apache.commons.net.util.SSLContextUtils;
import org.apache.commons.net.util.SSLSocketUtils;
import org.apache.commons.net.util.TrustManagerUtils;

/**
 * This class is a workaround for code introduced in commons-net 3.9.0 that breaks
 * FTPS support when HTTP proxies are used.
 * See https://issues.apache.org/jira/browse/NET-718
 * 
 * Derived from https://github.com/apache/commons-net/blob/master/src/main/java/org/apache/commons/net/ftp/FTPSClient.java
 * and https://github.com/apache/commons-net/blob/master/src/main/java/org/apache/commons/net/ftp/FTPClient.java
 */
final class LegacyFtpsClient extends FTPSClient {

    private Socket _openFTPDataConnection_(final String command, final String arg) throws IOException {
        final int dataConnectionMode = getDataConnectionMode();
        if (dataConnectionMode != ACTIVE_LOCAL_DATA_CONNECTION_MODE && dataConnectionMode != PASSIVE_LOCAL_DATA_CONNECTION_MODE) {
            return null;
        }
        final boolean isInet6Address = getRemoteAddress() instanceof Inet6Address;
        final Socket socket;
        final int soTimeoutMillis = toMillisInt(getDataTimeout());
        if (dataConnectionMode == ACTIVE_LOCAL_DATA_CONNECTION_MODE) {
            // if no activePortRange was set (correctly) -> getActivePort() = 0
            // -> new ServerSocket(0) -> bind to any free local port
            try (final ServerSocket server = _serverSocketFactory_.createServerSocket(getActivePort(), 1, getHostAddress())) {
                // Try EPRT only if remote server is over IPv6, if not use PORT,
                // because EPRT has no advantage over PORT on IPv4.
                // It could even have the disadvantage,
                // that EPRT will make the data connection fail, because
                // today's intelligent NAT Firewalls are able to
                // substitute IP addresses in the PORT command,
                // but might not be able to recognize the EPRT command.
                if (isInet6Address) {
                    if (!FTPReply.isPositiveCompletion(eprt(getReportHostAddress(), server.getLocalPort()))) {
                        return null;
                    }
                } else if (!FTPReply.isPositiveCompletion(port(getReportHostAddress(), server.getLocalPort()))) {
                    return null;
                }
                if (getRestartOffset() > 0 && !restart(getRestartOffset())) {
                    return null;
                }
                if (!FTPReply.isPositivePreliminary(sendCommand(command, arg))) {
                    return null;
                }
                // For now, let's just use the data timeout value for waiting for
                // the data connection. It may be desirable to let this be a
                // separately configurable value. In any case, we really want
                // to allow preventing the accept from blocking indefinitely.
                if (soTimeoutMillis >= 0) {
                    server.setSoTimeout(soTimeoutMillis);
                }
                socket = wrapOnDeflate(server.accept());
                // Ensure the timeout is set before any commands are issued on the new socket
                if (soTimeoutMillis >= 0) {
                    socket.setSoTimeout(soTimeoutMillis);
                }
                if (getReceiveDataSocketBufferSize() > 0) {
                    socket.setReceiveBufferSize(getReceiveDataSocketBufferSize());
                }
                if (getSendDataSocketBufferSize() > 0) {
                    socket.setSendBufferSize(getSendDataSocketBufferSize());
                }
            }
        } else {
            // We must be in PASSIVE_LOCAL_DATA_CONNECTION_MODE
            // Try EPSV command first on IPv6 - and IPv4 if enabled.
            // When using IPv4 with NAT it has the advantage
            // to work with more rare configurations.
            // E.g. if FTP server has a static PASV address (external network)
            // and the client is coming from another internal network.
            // In that case the data connection after PASV command would fail,
            // while EPSV would make the client succeed by taking just the port.
            final boolean attemptEPSV = isUseEPSVwithIPv4() || isInet6Address;
            if (attemptEPSV && epsv() == FTPReply.ENTERING_EPSV_MODE) {
                _parseExtendedPassiveModeReply(_replyLines.get(0));
            } else {
                if (isInet6Address) {
                    return null; // Must use EPSV for IPV6
                }
                // If EPSV failed on IPV4, revert to PASV
                if (pasv() != FTPReply.ENTERING_PASSIVE_MODE) {
                    return null;
                }
                _parsePassiveModeReply(_replyLines.get(0));
            }
            socket = wrapOnDeflate(_socketFactory_.createSocket());
            if (getReceiveDataSocketBufferSize() > 0) {
                socket.setReceiveBufferSize(getReceiveDataSocketBufferSize());
            }
            if (getSendDataSocketBufferSize() > 0) {
                socket.setSendBufferSize(getSendDataSocketBufferSize());
            }
            if (getPassiveLocalIPAddress() != null) {
                socket.bind(new InetSocketAddress(getPassiveLocalIPAddress(), 0));
            }
            // For now, let's just use the data timeout value for waiting for
            // the data connection. It may be desirable to let this be a
            // separately configurable value. In any case, we really want
            // to allow preventing the accept from blocking indefinitely.
            if (soTimeoutMillis >= 0) {
                socket.setSoTimeout(soTimeoutMillis);
            }
            socket.connect(new InetSocketAddress(getPassiveHost(), getPassivePort()), connectTimeout);
            if (getRestartOffset() > 0 && !restart(getRestartOffset())) {
                socket.close();
                return null;
            }
            if (!FTPReply.isPositivePreliminary(sendCommand(command, arg))) {
                socket.close();
                return null;
            }
        }
        if (isRemoteVerificationEnabled() && !verifyRemote(socket)) {
            // Grab the host before we close the socket to avoid NET-663
            final InetAddress socketHost = socket.getInetAddress();
            socket.close();
            throw new IOException(
                    "Host attempting data connection " + socketHost.getHostAddress() + " is not same as server " + getRemoteAddress().getHostAddress());
        }
        return socket;
    }

    private static Socket wrapOnDeflate(final Socket plainSocket) {
        switch (fileTransferMode) {
        case DEFLATE_TRANSFER_MODE:
            return new DeflateSocket(plainSocket);
        default:
            return plainSocket;
        }
    }

    private static int toMillisInt(final Duration duration) {
        final long millis = duration.toMillis();
        return millis > 0 ? (int) Math.min(millis, Integer.MAX_VALUE) : (int) Math.max(millis, Integer.MIN_VALUE);
    }

}
