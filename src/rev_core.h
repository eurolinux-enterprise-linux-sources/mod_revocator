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

    core functions not in NSPR or libc

    Julien Pierre
    Netscape Communications
    
    history
    
    27 Feb 2002 - start
        
*/

#ifndef __CRLCORE__
#define __CRLCORE__

#include "nspr.h"

#ifdef __cplusplus
extern "C"
{
#endif

char* Rev_Strdup(const char* instr);
char* Rev_StrNdup(const char* instr, PRInt32 inlen);
void* Rev_Malloc(const PRInt32 sz);
void Rev_Free(char* instr);
PRBool Rev_ParseString(const char* inputstring, const char delimiter, 
                       PRInt32* numStrings, char*** returnedstrings);
PRBool Rev_FreeParsedStrings(PRInt32 numStrings, char** instrings);

#ifdef __cplusplus
}
#endif

#endif

