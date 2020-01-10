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
#include "revocation.h"
#include "revprivate.h"
#include "rev_core.h"
#include <stdarg.h>

// global variables, for callbacks
RevocationFailureNotification failureCallback;
void* failureArg=NULL;
RevocationDownloadNotification notificationCallback;
void* notificationArg1=NULL;
void* notificationArg2=NULL;

// helper functions for C applications

extern "C" PR_IMPLEMENT(const char*) Rev_getMessage(const RevStatus* rv)
{
    return rv->getMessage();
}

extern "C" PR_IMPLEMENT(PRBool) Rev_hasFailed(const RevStatus* rv)
{
    return rv->hasFailed();
}

extern "C" PR_IMPLEMENT(PRInt32) Rev_getError(const RevStatus* rv)
{
    return rv->getError();
}

// callback helper setup functions

extern "C" PR_IMPLEMENT(void) Rev_SetFailureCallback(RevocationFailureNotification func, void* arg)
{
    failureCallback = func;
    failureArg = arg;
}

extern "C" PR_IMPLEMENT(void) Rev_SetDownloadCallback(RevocationDownloadNotification func, void* arg1, void *arg2)
{
    notificationCallback = func;
    notificationArg1 = arg1;
    notificationArg2 = arg2;
}

// private helper functions to call back into the application

void NotifyFailure(const char* url, const char* subject,
                   const RevStatus* theerror)
{
    // there was an error
    if (failureCallback)
    {
        // if we have a callback function, report it to the application
        (*failureCallback)(failureArg, url, subject, theerror);
    }
}

void NotifyDownload(const char* url, const char* subject, PRTime curtime,
                    PRTime lastupdate, PRTime nextupdate, PRTime maxage)
{
    if (notificationCallback)
    {
        // if we have a callback function, notify the application
        (*notificationCallback)(notificationArg1, notificationArg2, url,
                                subject, curtime, lastupdate, nextupdate,
                                maxage);
    }
}
