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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "ldap.h"
#include "ldap_ssl.h"
#include "nss.h"
#include "pk11func.h"

/*
 * Unit test program for ldap-client.
 *
 * To enable client-auth support:
 *
 * You need to modify ldap-client.cpp and modify the 3rd argument of
 * the call to ldapssl_enable_clientauth() to include the cert db password
 * of the database you are using. Don't make a mistake and check this in!
 * 
 * Some sample URLs to test with (using the GAT NES cert db):
 *
 * "ldap://nsdirectory/dc=netscape,dc=com?nscpAIMScreenName?sub?(uid=mcs)"
 * "ldaps://nsdirectory/dc=netscape,dc=com?nscpAIMScreenName?sub?(uid=mcs)"
 * "ldap://ultraman:3389/o=TestCentral?telephoneNumber?sub?(uid=alpha)?x-bindname=uid%3dalpha%2cou%3dPeople%2co%3dTestCentral,x-bindcredentials=YWxwaGE="
 * "ldaps://ultraman:6636/o=TestCentral?telephoneNumber?sub?(uid=alpha)?x-bindtlscertificatename=alpha,bindmechanism=EXTERNAL"
 *
 */

#define CERTPATH    "."

extern void *ldap_client(const char *url, int timeout, int *len, int *errnum);

int
main( int argc, char *argv[] )
{
    int            timeout = 10;    /* seconds */
    int            i, errnum, datalen;
    char        *datap, *p;
    const char    *url;

    if ( ldapssl_client_init( CERTPATH, NULL ) < 0 ) {
        perror( "ldapssl_client_init" );
        return 1;
    }

    for ( i = 1; i < argc; ++i ) {
        url = argv[i];

        printf( "------\nFetching data at %s...\n", url );
        errnum = datalen = -1;
        datap = (char *)ldap_client( url, timeout, &datalen, &errnum );
        printf( "CL error %d, data 0x%x, datalen %d\n",
                    errnum, datap, datalen );
        if ( datap != NULL ) {
            fputs( "Data: \"", stdout );
            p = datap;
            while ( datalen-- > 0 ) {
                putchar( *p );
                ++p;
            }
            fputs( "\"\n", stdout );
        }
        free( datap );
        datap = NULL;
    }

    return 0;
}
