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
 * Error codes used by URL getters
*/

#ifndef _CLIENT_ERR_H_
#define _CLIENT_ERR_H_

/* Here are the error return codes */

/* Generic error */
#define CL_URL_UNKNOWN	 	0

/* LDAP client errors */
#define CL_URL_ERR_NOTLDAP 	1
#define CL_URL_ERR_NODN 	2
#define CL_URL_ERR_BADSCOPE 	3
#define CL_URL_ERR_MEM 		4
#define CL_URL_ERR_UNKNOWN	5
#define CL_LDAP_NO_ATTRS	6
#define CL_LDAP_TOO_MANY_ATTRS	7
#define CL_LDAP_CONNECT_FAILED	8
#define CL_LDAP_BIND_FAILED	9
#define CL_LDAP_SEARCH_FAILED	10
#define CL_LDAP_NOT_ONE_ENTRY	11
#define CL_LDAP_ATTR_GET_FAILED	12
#define CL_LDAP_INVALID_CRED	13
#define CL_LDAP_AUTHBIND_FAILED	14
#define CL_LDAP_CLAUTH_INIT	15

/* HTTP client errors */
#define CL_URL_ERR_NOTHTTP	16
#define CL_HTTP_SOCKET_FAILED	17
#define CL_HTTP_DNS_FAILED	18
#define CL_HTTP_ENUMHOST	19
#define CL_HTTP_CONNECT_FAILED	20
#define CL_HTTP_WRITE_FAILED	21
#define CL_HTTP_READ_FAILED	22
#define CL_OUT_OF_MEMORY	23
#define CL_NOUPDATE_AVAILABLE   27

/* EXEC client errors */
#define CL_PIPE_FAILED          24
#define CL_FORK_FAILED          25
#define CL_EXEC_FAILED          26
 
#endif /* _CLIENT_ERR_H_ */
