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

    public interfaces for revocation engine
    to be used by SSL server applications

    Julien Pierre
    Netscape Communications
    
    history
    
    17 Jan 2002 - start
        
*/

#ifndef __REVOCATION__
#define __REVOCATION__

#include "nspr.h"
#include "secport.h"

#ifndef __REVOCATION_IMPLEMENTATION__
typedef void RevStatus;
#else
#include "status.h"
#endif

SEC_BEGIN_PROTOS

/* typedefs for application callback functions */
typedef PRBool (PR_CALLBACK* RevocationFailureNotification)(void* arg,
                                                        const char* url,
                                                        const char* subject,
                                                        const RevStatus* theerror);
typedef PRBool (PR_CALLBACK* RevocationDownloadNotification)(void* arg1,
                                                        void *arg2,
                                                        const char* url,
                                                        const char* subject,
                                                        PRTime curtime,
                                                        PRTime lastupdate,
                                                        PRTime nextupdate,
                                                        PRTime maxage);
/* typedefs to ease loading the helper symbols dynamically */
typedef char* (PR_CALLBACK* RevocationGetMessage)(const RevStatus* rv);
typedef PRBool (PR_CALLBACK* RevocationHasFailed)(const RevStatus* rv);
typedef PRInt32 (PR_CALLBACK* RevocationGetError)(const RevStatus* rv);

typedef void (PR_CALLBACK* Rev_SetFailureCallbackEntryPoint)(
                                        RevocationFailureNotification func,
                                        void* arg);

typedef void (PR_CALLBACK* Rev_SetDownloadCallbackEntryPoint)(
                                        RevocationDownloadNotification func,
                                        void* arg1,
                                        void* arg2);

/* helper functions for applications to retrieve error status */
PR_EXTERN(const char*) Rev_getMessage(const RevStatus* rv);
PR_EXTERN(PRBool) Rev_hasFailed(const RevStatus* rv);
PR_EXTERN(PRInt32) Rev_getError(const RevStatus* rv);
/* helper functions for applications to set failure and download callbacks */
PR_EXTERN(void) Rev_SetFailureCallback(RevocationFailureNotification func,
                                       void* arg);
PR_EXTERN(void) Rev_SetDownloadCallback(RevocationDownloadNotification func,
                                        void* arg1, void *arg2);

SEC_END_PROTOS

#include "reverror.h"

typedef const char* RevocationInitString;

/*
 
 configuration string to be passed to the PKCS#11 module at initialization time

 string format :
 URL;update-period;maxage <repeat>

*/

#endif

