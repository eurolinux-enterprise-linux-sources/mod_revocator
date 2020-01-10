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
#include "rev_core.h"
#include <stdarg.h>

// RevStatus C++ implementation

RevStatus :: RevStatus()
{
    failed = PR_FALSE;
    errorcode = 0;
    errmessage = NULL;
    needfree = PR_FALSE;
}

RevStatus :: RevStatus(PRInt32 error)
{
    RevStatus();
    setError(error);
}

RevStatus& RevStatus :: operator= (const RevStatus& rhs)
{
    failed = rhs.failed;
    errorcode = rhs.errorcode;
    needfree = rhs.needfree;
    if (needfree)
    {
        errmessage = Rev_Strdup(rhs.errmessage);
    }
    else
    {
        errmessage = rhs.errmessage;
    }
    return *this;
}

RevStatus :: RevStatus(const RevStatus& rhs)
{
    failed = rhs.failed;
    errorcode = rhs.errorcode;
    needfree = rhs.needfree;
    if (needfree)
    {
        errmessage = Rev_Strdup(rhs.errmessage);
    }
    else
    {
        errmessage = rhs.errmessage;
    }
}

RevStatus :: RevStatus(PRInt32 error, char* msg)
{
    RevStatus();
    setError(error, msg);
}

RevStatus :: RevStatus(PRInt32 error, const char* msg)
{
    RevStatus();
    setError(error, msg);
}

RevStatus :: RevStatus(PRInt32 error, const char* fmt, ...)
{
    RevStatus();
    
    va_list args;
    va_start(args, fmt);

    setDetailedErrorInternal(error, fmt, args);

    va_end(args);
}

void RevStatus :: clearMessage()
{
    if (PR_TRUE == needfree && errmessage)
    {
        Rev_Free(errmessage);
        needfree = PR_FALSE;
        errmessage = NULL;
    }
}

void RevStatus :: clearError()
{
    clearMessage();
    errorcode = 0;
    failed = PR_FALSE;
}

RevStatus :: ~RevStatus()
{
    clearMessage();
}

void RevStatus :: setError(PRInt32 error)
{
    clearError();
    failed = PR_TRUE;
    errorcode = error;
};

void RevStatus :: setError(PRInt32 error, char* msg)
{
    setError(error);
    errmessage = Rev_Strdup(msg);
    needfree = PR_TRUE;
}

void RevStatus :: setError(PRInt32 error, const char* msg)
{
    setError(error);
    errmessage = (char*)msg;
    needfree = PR_FALSE;
}

void RevStatus :: setDetailedErrorInternal(PRInt32 error, const char* fmt, va_list args)
{
    setError(error);
    char* msg = PR_vsmprintf(fmt, args);
    if (msg)
    {
        errmessage = Rev_Strdup(msg);
        needfree = PR_TRUE;
        PR_smprintf_free(msg);
    }
}

void RevStatus :: setDetailedError(PRInt32 error, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    setDetailedErrorInternal(error, fmt, args);

    va_end(args);
}

const char* RevStatus :: getMessage() const
{
    return errmessage;
}

const PRInt32 RevStatus :: getError() const
{
    return errorcode;
}

const PRBool RevStatus :: hasFailed() const
{
    return failed;
}


