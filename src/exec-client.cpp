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
 * exec-client.cpp - A client to execute a given program and return the
 *                   data over stdin.
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

PR_IMPLEMENT(void *)exec_client(const char *urlin, int timeout, int * len, int * errnum)
{
    char *cmd;
    char * separator;
    int pfildes[2];
    int pid;
    char * tmpurl = NULL;
    int ldap = 0;
    char * arg;
    char * args[32];
    int argcnt = 0;

    tmpurl = strdup(urlin);

    *len = 0;

    cmd = (char *)tmpurl + 7; /* skip resource type */

    memset( &args[0], 0, sizeof( args ));
    arg = cmd;

    while (arg != 0 && *arg != 0 && argcnt < 32) {
        if ((separator = strchr(arg, '|')) != NULL) {
            *separator++ = 0;
        }
        args[argcnt++] = arg;
        arg = separator;
    }

    ldap = !PL_strncasecmp(args[argcnt-1], "ldap", 4);
    uri_unescape_strict((char *)args[argcnt-1], ldap); // decode just the URL passed in

    if (pipe(pfildes) < 0) {
        *errnum = CL_PIPE_FAILED;
        free(tmpurl);
        return NULL;
    }

    if ((pid = fork()) == -1) {
        *errnum = CL_FORK_FAILED;
        free(tmpurl);
        return NULL;
    }

    if (pid == 0) { /* child */
        close(pfildes[0]);
        dup2(pfildes[1],1);
        close(pfildes[1]);
        execv(cmd, args);
        free(tmpurl);
        _exit(0);
    }
    else { /* parent */
        void * data = 0;
        int sz = BIG_LINE * 4;
        char buffer[BIG_LINE * 4];
        int numbytes, totalread;
        data = (void *) malloc(BIG_LINE * 4); // Start with a 4k block
        int done = 0;

        close(pfildes[1]);
        dup2(pfildes[0],0);
        close(pfildes[0]);

        totalread = 0;
        do {
            numbytes = read(0, buffer, (BIG_LINE * 4) - 1);
            if (numbytes > 0) {
                buffer[numbytes] = '\0';
                totalread += numbytes;
                if (totalread >= sz) {
                    // We need to realloc, add 4k more
                    void* olddata = data;
                    data = (void *) realloc(olddata, totalread+(BIG_LINE * 4));
                    if (!data) {
                        if (olddata)
                        {
                            free(olddata);
                        }
                        *errnum = CL_OUT_OF_MEMORY;
                        free(tmpurl);
                        return NULL;
                    }
                    sz += (BIG_LINE * 4);
                }
                memcpy((char *)data+totalread-numbytes, buffer, numbytes);
            } else if (numbytes < 0) {
                *errnum = CL_HTTP_READ_FAILED;
                if (data) free(data);
                data = 0;
                free(tmpurl);
                return NULL;
            } else if (numbytes == 0) {
                done = 1;
            }
        }
        while (!done); 

        if (totalread == 0) {
            free(data);
            data = NULL;
        }
        free(tmpurl);
        *len = totalread;
        return data;
    }
}
