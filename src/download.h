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

    download interfaces for CRLs from HTTP, HTTPS, LDAP and LDAPS

    Julien Pierre
    Netscape Communications
    
    history
    
    17 Jan 2002 - start
        
*/

#ifndef __CRLDOWNLOAD__
#define __CRLDOWNLOAD__

#include "nspr.h"
#include "revocation.h"


/* DownloadCRL is responsible for parsing, validating the CRL download URL,
   and then performing the download of the CRL, returning it as a blob of
   data in a SECItem.
   
   Returns :
   SECFailure or SECSuccess
   upon SECSuccess : CRL in output
   upon SECFailure : error string in returned_error
*/

RevStatus DownloadCRL(const char* url, const PRIntervalTime timeout, SECItem& output);

#endif

