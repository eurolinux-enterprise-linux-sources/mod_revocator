/** BEGIN COPYRIGHT BLOCK
 * Copyright (c) 2006  Red Hat, Inc. All rights reserved.
 * 
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions of
 * the Apache License, 2.0.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY expressed or implied, including the implied warranties of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  A copy of this
 * license is available at http://www.opensource.org/licenses.  Any Red Hat
 * trademarks that are incorporated in the source code or documentation are
 * not subject to the Apache License, 2.0 and may only be used or replicated
 * with the express permission of Red Hat, Inc.
 * 
 * Red Hat Author(s): Rob Crittenden
 * END COPYRIGHT BLOCK **/
/* 
 *
 * http-client.cpp - A very basic HTTP/HTTPS client
 * 
 */

#include <prerror.h>
#include <prtypes.h>
#include <ssl.h>
#include <nss.h>
#include <sslerr.h>
#include <sslproto.h>
#include <base64.h>

#include <stdlib.h>
#include <string.h>

#ifdef XP_UNIX
#include <sys/types.h>
#include <unistd.h>
#endif

#include "client.h"
#include "client_err.h"
#include "unescape.h"

#define BIG_LINE 1024

/* Carriage return and line feed */
#define CR 13
#define LF 10

/* return codes for PR_Recv */
#define IO_ERROR -1
#define IO_EOF 0

#ifndef PRODUCT_BRAND_NAME
#define PRODUCT_BRAND_NAME "NetscapeCRL"
#define PRODUCT_VERSION_ID "1.0"
#endif

/* local declarations */
/*
int parse_url(const char *url, char **username, char **password, char **protocol , char **host, int *port, char **uri);
*/
static int certcallback(void *arg, PRFileDesc * fd, PRBool checksig,
                        PRBool isServer);
PRFileDesc *create_socket(int ssl);
SECStatus ownBadCertHandler(void *arg, PRFileDesc * socket);
SECStatus ownHandshakeCallback(PRFileDesc * socket, void *arg);
int writeThisMany(PRFileDesc * fd, char *buffer, int thisMany, int timeout);
int get_content_length(PRFileDesc * sock, int timeout);

/* Generic secure/non-secure HTTP client. It determines whether it should
 * use SSL automatically based on the URL it is passed.
 *
 * Return any data read by the server. It is up to the caller to free the
 * returned data. Returns NULL upon failure.
 *
 * The timeout is in seconds.
*/
PR_IMPLEMENT(void *)http_client(const char *url, int timeout,
                                PRTime lastfetchtime, int * len, int * errnum)
{
    char * protocol = 0;
    char * host = 0;
    char * username = 0;
    char * password = 0;
    int port;
    char * uri = 0;
    PRFileDesc *sock = 0;
    PRNetAddr addr;
    PRUint32 numbytes;
    PRInt32 totalread, sz;
    PRHostEnt hostentry;
    char buffer[BIG_LINE * 4];
    char hostline[BIG_LINE];
    void *data = 0;
    char *authdata = 0;
    PRInt32 cl = 0;
    int ssl = 0;
    unsigned int lenp;
    PRExplodedTime printableTime;
    char ifmodified[256];
   
    uri_unescape_strict((char *)url, 0); // decode the url

    if (!parse_url(url, &username, &password, &protocol, &host, &port, &uri)) {
        *errnum = CL_URL_ERR_NOTHTTP;
        return NULL;
    }

    if (!PL_strcasecmp(protocol, "https"))
        ssl = 1;

    if ((sock = create_socket(ssl)) == NULL) {
        *errnum = CL_HTTP_SOCKET_FAILED;
        goto done;
    }

    /* prepare and setup network connection */
    if (PR_GetHostByName(host, buffer, (BIG_LINE * 4), &hostentry) != PR_SUCCESS) {
        *errnum = CL_HTTP_DNS_FAILED;
        goto done;
    }

    if (PR_EnumerateHostEnt(0, &hostentry, port, &addr) < 0) {
        *errnum = CL_HTTP_ENUMHOST;
        goto done;
    }

    if (PR_Connect(sock, &addr, PR_SecondsToInterval(timeout)) == PR_FAILURE) {
        *errnum = CL_HTTP_CONNECT_FAILED;
        goto done;
    }

    /* Handle basic authentication */
    if (username && password) {
        PR_snprintf(buffer, sizeof(buffer),"%s:%s", username, password);
        /* Convert the whole string to base-64 encoding */
        lenp = strlen((const char *)buffer);
        authdata = BTOA_DataToAscii((const unsigned char *)buffer, lenp);
    }

    if ((port == 443) || (port == 80))
        strncpy(hostline, host, BIG_LINE);
    else
        PR_snprintf(hostline, sizeof(hostline), "%s:%d", host, port);

    memset(ifmodified, 0, 256);
    if (lastfetchtime > 0) {
        PR_ExplodeTime(lastfetchtime, PR_GMTParameters, &printableTime);
        PR_FormatTime(ifmodified, 256, "%a, %d %b %Y %H:%M:%S GMT", &printableTime);
    }
    
    /* Construct the HTTP request */
    PR_snprintf(buffer, sizeof(buffer),
        "GET %s HTTP/1.1\r\n"
        "%s%s%s"
        "Host: %s\r\n"
        "User-Agent: %s/%s\r\n"
        "%s%s%s"
        "Connection: close\r\n\r\n",
        uri, 
        authdata ? "Authorization: Basic " : "", authdata ? authdata: "", authdata ? "\r\n" : "", 
        hostline,
        PRODUCT_BRAND_NAME, PRODUCT_VERSION_ID,
        ifmodified[0] ? "If-Modified-Since: " : "", ifmodified[0] ? ifmodified : "", ifmodified[0] ? "\r\n" : "");

    if (authdata)
        free(authdata);

    numbytes = writeThisMany(sock, buffer, strlen(buffer), timeout);

    if (numbytes != strlen(buffer)) {
        *errnum = CL_HTTP_WRITE_FAILED;
        goto done;
    }

    /* a content-length of -1 means read until there is no more to read */
    cl = get_content_length(sock, timeout);
    if (cl == -2) {
        cl = 0; /* so we don't end up with a bogus len in done: */
        *errnum = CL_NOUPDATE_AVAILABLE;
        goto done;
    }
    if (cl != 0) {

        totalread = 0;
        sz = 4096;
        data = (void *) malloc(4096); // Start with a 4k block

        do {
            numbytes = PR_Recv(sock, buffer, (BIG_LINE * 4) - 1, 0, PR_SecondsToInterval(timeout));
            if (numbytes > 0) {
                buffer[numbytes] = '\0';
                totalread += numbytes;
		if (totalread >= sz) {
                    // We need to realloc, add 4k more
                    void* olddata = data;
                    data = (void *) realloc(olddata, totalread+4096);
                    if (!data) {
                        if (olddata)
                        {
                            free(olddata);
                        }
                        *errnum = CL_OUT_OF_MEMORY;
                        goto done;
                    }
                    sz += 4096;
                }
                memcpy((char *)data+totalread-numbytes, buffer, numbytes);
            } else if (numbytes < 0) {
                *errnum = CL_HTTP_READ_FAILED;
                if (data) free(data);
                cl = 0;
                data = 0;
                goto done;
            } else if (numbytes == 0) {
                cl = totalread;   
            }
        }
        while ((totalread < cl) || (cl == -1)); // need more or don't know size
    } else {
        *errnum = CL_HTTP_READ_FAILED;
    }

done:

    PR_Close(sock);
    if (protocol) free(protocol);
    if (host) free(host);
    if (uri) free(uri);
    if (username) free(username);
    if (password) free(password);

    *len = cl;
    return (data);
}

/* Parse the url into it's component pieces 
 *
 * protocol://username:password@hostname:port/path/filename 
 *
 * The caller must free the URL components
 */
int parse_url(const char *url, char **username, char **password, 
              char **protocol, char **host, int *port, char **uri)
{
    char *tmp;
    char *tmphost;
    char *work = 0;
    char s_port[16];
    char *s, *u;

    /* make a working copy of the url */
    work = strdup(url);

    /* Find the protocol */
    tmp = (char *) strchr(work, ':');
    if (!tmp) {
        free(work);
        return 0;
    }

    *tmp++ = '\0';
    *protocol = (char *)malloc(strlen(work) + 1);
    strcpy(*protocol, (char *) work);

    if (PL_strcasecmp((char *) *protocol, "http")
        && PL_strcasecmp((char *) *protocol, "https")) {
        free(work);
        return 0;
    }

    /* skip // after the protocol */
    if ((*tmp++ != '/') || (*tmp++ != '/')) {
        free(work);
        return 0;
    }

    /* if there is an @ then there is a username/password in the URL */
    if ((s = (char *)strchr(tmp, '@')) != NULL) {
        *s++ = '\0';
        *username = (char *)malloc(strlen(tmp) + 1);
        strcpy(*username, (char *) tmp);
        u = (char *)strchr(*username, ':');
        if (u) {
            *u++ = '\0';
            *password = (char *)malloc(strlen(u) + 1);
            strcpy(*password, (char *) u);
        } else {
            free(work);
            return 0;
        }
        tmp = s;
    }
    tmphost = tmp;

    /* find the port */
    while (*tmp && (*tmp != ':') && (*tmp != '/'))
        tmp++;

    memset(s_port, 0, 16);

    if (*tmp == ':') {
        int i = 0;
        /* scan for port string */
        *tmp++ = '\0';  /* we have the host name */
        while (*tmp && isdigit(*tmp)) {
            s_port[i++] = *tmp++;
        }
        if ((*tmp && *tmp != '/') || !*s_port) {
            free(work);
            return 0;
        }
    }

    if (*s_port)
        *port = atoi(s_port);
    else {
        if (!strcmp(*protocol, "https"))
            *port = 443;
        else
            *port = 80;
    }

    /* get the hostname */
    if (*tmp && *tmp == '/') {
        *tmp = '\0'; /* we have the host name */
        tmp++;
    }

    /* Make a copy of the URI */
    *uri = (char *)malloc(strlen(tmp) + 3);
    snprintf(*uri, strlen(tmp)+2, "/%s", tmp);

    /* Make a copy of the server name */
    *host = (char *)malloc(strlen(tmphost) + 1);
    strcpy(*host, tmphost);

    free(work);

    return 1;
}

/* Function: int writeThisMany()
 *
 * Purpose: This is a wrapper function around PR_Send that will write exactly
 * the number of bytes requested and return the number of bytes written.
 */
int writeThisMany(PRFileDesc * fd, char *buffer, int thisMany, int timeout)
{

    int total = 0;

    while (total < thisMany) {

        int got;

        got = PR_Send(fd, buffer + total, thisMany - total, 0, PR_SecondsToInterval(timeout));
        if (got < 0) {
            if (PR_GetError() != PR_WOULD_BLOCK_ERROR) {
                break;
            }
            continue;
        }

        total += got;
    }

    return total;
}

/* The only header I'm interested in is Content-length but go ahead and eat
 * all of them.
 * 
 * based on scan_cgi_headers
 *
 * Returns either:
 *   > 0, the server returned a "Content-length" header
 *     0, a network error or EOF occured
 *    -1, the server didn't return a "Content-length" and no error
 */
int get_content_length(PRFileDesc * sock, int timeout)
{
    register int x, y;
    int nh, i;
    char c, buffer[1];
    char t[1024];
    char *header;
    int length = 0;

    nh = 0;
    x = 0;
    y = -1;

    while (1) {
        i = PR_Recv(sock, buffer, 1, 0, PR_SecondsToInterval(timeout));
        if ((i == IO_ERROR) || (i == IO_EOF))
            return 0;
        c = buffer[0];

        switch (c) {
        case LF:
            if ((!x) || ((x == 1) && (t[0] == CR))) {
                if (length == 0)
                    return -1; /* didn't get a Content-length header */
                else
                    return length;
            }

            if (t[x - 1] == CR)
                --x;
            t[x] = '\0';
            if ((y == -1) && (nh > 0)) {
                return 0; /* name without value */
            }
            while (t[y] && isspace(t[y]))
                ++y;

            header = strtok(t, ":");
            if (header) {
                char *s = t;
                s += 9; /* skip 'http/1.x ' */
                if (s && !PL_strncmp(s, "304", 3))
                    length = -2;
                else if (!PL_strcasecmp("content-length", header))
                    length = atoi(&t[y]);
            }

            x = 0;
            y = -1;
            ++nh;
            break;
        case ':':
            if (y == -1) {
                y = x + 1;
                c = '\0';
            }
        default:
#if defined(SNI)
            {
                int d = tolower(c);
                t[x++] = ((y == -1) && isupper(c) ? d : c);
            }
#else
            t[x++] = ((y == -1) && isupper(c) ? tolower(c) : c);
#endif
        }
    }
}

PRFileDesc *create_socket(int ssl)
{
    PRFileDesc *socket = NULL;
    PRSocketOptionData sockdata;

    socket = PR_NewTCPSocket();

    if (!socket) {
        return NULL;
    }

    /* Ensure that the socket is blocking. The default on some platforms
     * is non-blocking
     */
    sockdata.option = PR_SockOpt_Nonblocking;
    sockdata.value.non_blocking = PR_FALSE;

    if (PR_SetSocketOption(socket, &sockdata) != PR_SUCCESS) {
        return NULL;
    }

    /* If SSL is requested then we need to do some additional work */
    if (ssl) {

        socket = SSL_ImportFD(NULL, socket);

        if ((SSL_OptionSet(socket, SSL_NO_CACHE, 1)) != SECSuccess) {
            return NULL;
        }

        if ((SSL_OptionSet(socket, SSL_SECURITY, 1)) != SECSuccess)
            return NULL;

        if ((SSL_OptionSet(socket, SSL_HANDSHAKE_AS_CLIENT, 1)) != SECSuccess)
            return NULL;

        SSL_AuthCertificateHook(socket, (SSLAuthCertificate)certcallback, (void *)CERT_GetDefaultCertDB());

        if ((SSL_BadCertHook(socket, (SSLBadCertHandler) ownBadCertHandler,
                             NULL)) != SECSuccess)
            return NULL;

        if ((SSL_HandshakeCallback(socket,
                                   (SSLHandshakeCallback)
                                   ownHandshakeCallback,
                                   NULL)) != SECSuccess) return NULL;
    }

    /* Return the address of the configured socket */
    return socket;
}

/* Check the validity of the server cert */
static int certcallback(void *arg, PRFileDesc * fd, PRBool checksig,
                        PRBool isServer)
{
    SECCertUsage        certUsage;
    CERTCertificate *   cert;
    void *              pinArg;
    SECStatus           rv              = SECFailure;

    if (!fd) {
        return rv;
    }

    if (!arg) {
        // we don't have a trust domain and are therefore running inside
        // of an unmodified NSS app. The only way to let the download
        // happen is to return SECSuccess . This isn't secure and is for
        // testing only.
        rv = SECSuccess;
        return rv;
    }

    certUsage = isServer ? certUsageSSLClient : certUsageSSLServer;

    cert = SSL_PeerCertificate(fd);

    pinArg = SSL_RevealPinArg(fd);

    rv = CERT_VerifyCertNow((CERTCertDBHandle*)arg,
                             cert,
                             checksig,
                             certUsage,
                             pinArg);
    if ( (rv != SECSuccess) || isServer ) {
        return rv;
    }

    CERT_DestroyCertificate(cert);

    return rv;
}

SECStatus ownBadCertHandler(void *arg, PRFileDesc * socket)
{

    /* Note here that this particular callback implementation always
     * rejects a bad cert.
     */
    return SECFailure;
}

/* Function: SECStatus ownHandshakeCallback()
 *
 * Purpose: Called by SSL to inform application that the handshake is
 * complete. This function is mostly used on the server side of an SSL
 * connection, although it is provided for a client as well.
 */

SECStatus ownHandshakeCallback(PRFileDesc * socket, void *arg)
{
    return SECSuccess;
}
