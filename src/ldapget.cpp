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
 * Command-line program to fetch a single attribute and return it via
 * stdout. This is meant to be used in conjunction with exec-client.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "ldap.h"
#ifdef MOZILLA_LDAP
#include "ldap_ssl.h"
#endif
#include "nss.h"
#include "pk11func.h"

/* No sense in re-inventing the wheel. Use the existing LDAP client to
 * retrieve the data, we'll just return it via stdout instead */
extern void *ldap_client(const char *url, int timeout, int *len, int *errnum);

/*
 * Usage: ldapget [/path/to/certificate/database] ldap://url
 */
int
main( int argc, char **argv )
{
    int         timeout = 10;    /* seconds */
    int         i, errnum, datalen;
    char       *datap, *p;
    const char *url;

    if (argc < 2 || argc > 4) {
        printf("Usage: %s <NSS database> url\n", argv[0]);
        return 1;
    }

    if (argc == 3) {
#ifdef MOZILLA_LDAP
        if ( ldapssl_client_init( argv[1], NULL ) < 0 ) {
            return 1;
        }
#endif
        url = argv[2];
    } else {
        url = argv[1];
    }

    errnum = datalen = -1;
    datap = (char *)ldap_client( url, timeout, &datalen, &errnum );

#ifdef DEBUG
    printf( "CL error %d, data 0x%x, datalen %d\n",
                errnum, datap, datalen );
#endif
    if ( datap != NULL ) {
        p = datap;
        while ( datalen-- > 0 ) {
            putchar( *p );
            ++p;
        }
    }
    free( datap );
    datap = NULL;

    return 0;
}
