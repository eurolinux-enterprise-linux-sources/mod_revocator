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
    
    08 Mar 2002 - start
        
*/

#ifndef __REV_PRIVATE__
#define __REV_PRIVATE__

#include "nspr.h"
#include "secport.h"

#include "revocation.h"

void NotifyFailure(const char* url, const char* subject,
                   const RevStatus* theerror);
void NotifyDownload(const char* url, const char* subject, PRTime curtime = 0,
                    PRTime lastupdate = 0, PRTime nextupdate = 0,
                    PRTime maxage = 0);

#endif

