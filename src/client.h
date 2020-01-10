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
 * public interfaces URL getters
 *
*/

#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <nspr.h>
#define __REVOCATION_IMPLEMENTATION__ 1
#include "revocation.h"

PR_IMPLEMENT(void *)get_crl(int infd, int outfd, const char * url, int timeout, PRTime lastfetchtime, int * len, RevStatus& status);

PR_EXTERN(void *)fetch_url(const char * url, int timeout, PRTime lastfetchtime, int * len, int * errnum);

PR_EXTERN(void)free_url(void* urldata);

PR_EXTERN(void *)http_client(const char *url, int timeout, PRTime lastfetchtime, int * len, int * errnum);

int parse_url(const char *url, char **username, char **password, char **protocol , char **host, int *port, char **uri);

PR_EXTERN(void *)ldap_client(const char *url, int timeout, int * len, int * errnum);
PR_EXTERN(void *)exec_client(const char *url, int timeout, int * len, int * errnum);


#endif /* _CLIENT_H_ */
