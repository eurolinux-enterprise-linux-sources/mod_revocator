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
#include "rev_core.h"
#include <string.h>
#include "nspr.h"

extern "C"
char* Rev_Strdup(const char* instr)
{
    if (!instr)
    {
        return NULL;
    }
    
    size_t len = strlen(instr);
    return Rev_StrNdup(instr, len);
}

extern "C"
char* Rev_StrNdup(const char* instr, PRInt32 inlen)
{
    if (!instr)
    {
        return NULL;
    }
    
    size_t len = inlen;
    if (!len)
    {
        return NULL;
    }
    // use PR_Malloc. This will take advantage of the zone allocator
    char* buffer = (char*)Rev_Malloc(len+1);
    if (!buffer)
    {
        return NULL;
    }
    memcpy(buffer, instr, len);
    buffer[len] = 0; // NULL termination
    return buffer;
}

extern "C"
void Rev_Free(char* instr)
{
    if (!instr)
    {
        PR_ASSERT(0);
    }
    PR_Free(instr);
}

void addString(char*** returnedstrings, char* newstring, PRInt32 stringcount)
{
    char** stringarray = NULL;
    if (!returnedstrings || !newstring)
    {
        return;
    }
    if (!stringcount)
    {
        // first string to be added, allocate buffer
        *returnedstrings = (char**)PR_Malloc(sizeof(char*)*(stringcount+1));
        stringarray = *returnedstrings;
    }
    else
    {
        stringarray = (char**)PR_Realloc(*returnedstrings,
                                      sizeof(char*)*(stringcount+1));
        if (stringarray)
        {
            *returnedstrings = stringarray;
        }
    }
    if (stringarray)
    {
        stringarray[stringcount] = newstring;
    }
}

extern "C"
PRBool Rev_ParseString(const char* inputstring, const char delimiter, 
                       PRInt32* numStrings, char*** returnedstrings)
{
    if (!inputstring || !delimiter || !numStrings || !returnedstrings)
    {
        // we need a string and a non-zero delimiter, as well as
        // a valid place to return the strings and count
        return PR_FALSE;
    }
    char nextchar;
    char* instring = (char*) inputstring;
    *numStrings=0;
    *returnedstrings = NULL;

    while ((nextchar=*instring))
    {
        unsigned long len = 0;
        char* next = (char*)strchr(instring, delimiter);
        if (next)
        {
            // current string string
            len = next - instring;
        }
        else
        {
            // last string length
            len = strlen(instring);
        };

        if (len > 0) {
        char* newstring = Rev_StrNdup(instring, len);

        addString(returnedstrings, newstring, (*numStrings)++);

        instring+= len;
        }

        if (delimiter == *instring)
        {
            instring++; // skip past next delimiter
        };
    }
    return PR_TRUE;
}

extern "C"
PRBool Rev_FreeParsedStrings(PRInt32 numStrings, char** instrings)
{
    if (!numStrings || !instrings)
    {
        return PR_FALSE;
    }
    PRInt32 counter;
    for (counter=0;counter<numStrings;counter++)
    {
        char* astring = instrings[counter];
        if (astring)
        {
            Rev_Free(astring);
        }
    }
    PR_Free((void*)instrings);
	return PR_TRUE;
}

extern "C"
void* Rev_Malloc(const PRInt32 sz)
{
    return PR_Malloc(sz);
}

