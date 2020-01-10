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

    private interfaces for revocation engine
    to be used by SSL server applications

    Julien Pierre
    Netscape Communications
    
    history
    
    08 Mar 2002 - start
        
*/

#ifndef __REV_STATUS__
#define __REV_STATUS__

#include "nspr.h"
#include "secport.h"

class RevStatus
{
    public:
        RevStatus();
        RevStatus(const RevStatus& rhs);
        RevStatus(PRInt32 error);
        RevStatus(PRInt32 error, char* msg);
        RevStatus(PRInt32 error, const char* msg);
        RevStatus(PRInt32 error, const char* fmt, ...);
        ~RevStatus();
        RevStatus& operator= (const RevStatus& rhs);

        void clearMessage();
        void clearError();

        void setError(PRInt32 error);
        void setError(PRInt32 error, char* msg);
        void setError(PRInt32 error, const char* msg);
        void setDetailedError(PRInt32 error, const char* fmt, ...);

        const PRBool hasFailed() const;
        const PRInt32  getError() const;
        const char* getMessage() const;

    private:
        void setDetailedErrorInternal(PRInt32 error, const char* fmt, va_list args);
        PRBool failed;
        PRInt32 errorcode;
        char* errmessage;
        PRBool needfree;
};

#endif

