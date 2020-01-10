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
 * client.cpp - A wrapper around generic URL-getters
 * 
 */

#include <unistd.h>
#include <string.h>

#include "client.h"
#include "client_err.h"
#include "rev_core.h"

typedef struct client_error_t {
    int errorNumber;
    const char *errorString;
} client_error_t;

/* see client_err.h for the defines */

client_error_t client_errors[] = {
    { 0, "URL does not begin with \"ldap\" or \"http\"" },
    { 1, "URL does not begin with \"ldap://\"" },
    { 2, "URL missing trailing slash after host or port" },
    { 3, "URL contains an invalid scope" },
    { 4, "URL parsing ran out of memory" },
    { 5, "URL parsing unknown error" },
    { 6, "No attributes defined" },
    { 7, "Too many attributes, only 1 allowed" },
    { 8, "LDAP connection failed" },
    { 9, "Unable to anonymously bind to ldap server" },
    { 10, "ldap_search_st() failed" },
    { 11, "0 or more than 1 matches were returned" },
    { 12, "Unable to get attributes" },
    { 13, "Problem with LDAP credentials" },
    { 14, "Unable to bind to ldap server" },
    { 15, "Unable to enable LDAP client authentication" },
    { 16, "Unable to parse http[s] URL" },
    { 17, "Unable to create client socket" },
    { 18, "DNS lookup failed" },
    { 19, "PR_EnumerateHostEnt failed" },
    { 20, "Unable to connect to remote host" },
    { 21, "Unable to write data to remote server" },
    { 22, "Unable to read data from remote server" },
    { 23, "Out of memory while reading data" },
    { 24, "Pipe failed" },
    { 25, "Fork failed" }, 
    { 26, "Exec failed" },
    { 27, "HTTP 304 Not Modified returned. The CRL hasn't changed since the last retrieval." }
};

/*
 * Wrapper function for fetch_url().
 *
 * This communicates across a pipe to retrieve a CRL from the crlhelper
 * program and handles creating the status entry based on the returned
 * errnum.
 */
PR_IMPLEMENT(void *)get_crl(int infd, int outfd, const char * url, int timeout, PRTime lastfetchtime, int * len, RevStatus& status) 
{
    int errnum = -1;
    int nbytes;
    PRInt32 elements = 0;
    char **values=NULL;
    PRBool header_done=PR_FALSE;
    char *data = NULL;
    int totalread = 0;
    int sz = 4096;
    char buffer[4096];
    int toread = 0;

    if (!url) {
        status.setError(REV_ERROR_INVALID_URL_TYPE, client_errors[errnum].errorString);
    }

    if (!status.hasFailed()) {
        data = (char *)malloc(4096);
        *len = 0;

        /* Place the request to our crlhelper via the pipe */
        PR_snprintf(buffer, sizeof(buffer), "%lld %s", lastfetchtime, (char *)url);
        nbytes = write(outfd, buffer, strlen(buffer));
        if (nbytes == -1) {
            status.setError(REV_ERROR_INVALID_URL_TYPE, client_errors[CL_HTTP_WRITE_FAILED].errorString);
            goto done;
        }

        /* There are two conditions here:
         * 1. We haven't read the header yet with the errnum & len
         * 2. We haven't slurped in the rest of the data.
         *
         * The idea here is to read the header to figure out much data
         * to expect, then read it all in.
         */
        while (PR_FALSE == header_done || toread > 0) {
            int i;

            nbytes=read(infd, buffer, 4096);

            if (nbytes > 0) {
                totalread += nbytes;
                if (totalread >= sz) {
                    // We need a bigger buffer
                    char * olddata = data;
                    data = (char *) realloc(olddata, totalread+4096);
                    if (!data) {
                        if (olddata) {
                            free(olddata);
                        }
                        errnum = CL_OUT_OF_MEMORY;
                        goto done;
                    }
                    sz += 4096;
                }
                memcpy((char *)data+totalread-nbytes, buffer, nbytes);
            }
            if (*len == 0)
                Rev_ParseString((const char *)data, ' ', &elements, &values);
            if (PR_FALSE == header_done && elements > 2) {
                int data_read, header_len;
                errnum = strtol(values[0], NULL, 10);
                *len = strtol(values[1], NULL, 10);
                header_len = (strlen(values[0]) + strlen(values[1]) + 2);
                data_read = totalread - header_len;
                toread = *len - data_read;
                totalread = totalread - header_len;
                header_done = PR_TRUE;
                if (data_read > 0) {
                    memmove(data, (char *)data + header_len, data_read);
                    data[data_read+1] = '\0';
                } else {
                    totalread = 0;
                }
            } else if (PR_TRUE == header_done) {
                toread = *len - totalread;
            }
            Rev_FreeParsedStrings(elements, values);
            elements = 0;
        }

        data[*len] = '\0';
    }
done:

    if (errnum == CL_NOUPDATE_AVAILABLE) {
        status.setError(REV_ERROR_NOUPDATE_AVAILABLE, client_errors[errnum].errorString);
    } else if (errnum != -1) {
        status.setError(REV_ERROR_INVALID_URL_TYPE, client_errors[errnum].errorString);
    }

    return data;
}

/* Given a URL, determine the type and fetch the appropriate contents and 
 * return them.
 *
 * url - currenly supports HTTP[S] and LDAP[S] URLs
 * timeout - timeout in seconds for network connections, reads and writes
 * len - the length of the data returned
 * RevStatus - contains any error codes and messages
 *
 * NOTE: The caller is responsible for freeing any data that is returned.
 *
 * See the ldap-client.cpp and http-client.cpp for specific URL syntax.
 */
PR_IMPLEMENT(void *)fetch_url(const char * url, int timeout, PRTime lastfetchtime, int * len, int * errnum) 
{
    void * data = NULL;
    
    *errnum = -1;

    if (url) {
        if (!PL_strncasecmp(url, "ldap", 4))
            data = ldap_client(url, timeout, len, errnum);
        else if (!PL_strncasecmp(url, "http", 4))
            data = http_client(url, timeout, lastfetchtime, len, errnum);
        else if (!PL_strncasecmp(url, "exec", 4))
            data = exec_client(url, timeout, len, errnum);
        else
            errnum = CL_URL_UNKNOWN;
    }

    return data;
}

PR_IMPLEMENT(void)free_url(void* urldata)
{
    PR_ASSERT(urldata);
    free(urldata);
}

