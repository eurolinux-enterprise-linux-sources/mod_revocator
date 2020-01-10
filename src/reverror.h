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

#ifndef __REVOCATION_ERRORS__
#define __REVOCATION_ERRORS__

#include "nspr.h"
/*
    error codes passed in through RevStatus
*/

const PRInt32 REV_BASE_ERROR = 1000;
const PRInt32 REV_ERROR_BAD_CONFIG_STRING   = 1001;
const PRInt32 REV_ERROR_DOWNLOAD_FAILED     = 1002;
const PRInt32 REV_ERROR_INVALID_URL_TYPE    = 1003;
const PRInt32 REV_ERROR_OUT_OF_MEMORY       = 1004;
const PRInt32 REV_ERROR_INITIAL_DL_FAILED   = 1005;
const PRInt32 REV_ERROR_START_FAILURE       = 1006;
const PRInt32 REV_ERROR_BAD_DER_CRL         = 1007;
const PRInt32 REV_ERROR_UNKNOWN_ISSUER      = 1008;
const PRInt32 REV_ERROR_BAD_CRL_SIG         = 1009;
const PRInt32 REV_ERROR_BAD_CRL_STRING      = 1010;
const PRInt32 REV_ERROR_INVALID_TIME        = 1011;
const PRInt32 REV_ERROR_CRL_SUBJECT_CHANGED = 1012;
const PRInt32 REV_ERROR_BAD_ISSUER_USAGE    = 1013;
const PRInt32 REV_ERROR_MISSING_CRL_DATA    = 1014;
const PRInt32 REV_ERROR_BAD_ISSUER_TRUST    = 1015;
const PRInt32 REV_ERROR_NOUPDATE_AVAILABLE  = 1016;

#endif

