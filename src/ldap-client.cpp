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
 *
 * ldap-client.cpp - A basic LDAP/LDAPS client
 *
 */

#define LDAP_DEPRECATED 1
#include <ldap.h>
#ifdef MOZILLA_LDAP
#include <ldappr.h>
#include <ldap_ssl.h>
#endif
#include <ssl.h>
#include <string.h>
#ifdef MCS_STANDALONE
#include <stdio.h>
#else   /* MCS_STANDALONE */
#include "client.h"
#endif  /* MCS_STANDALONE */
#include "client_err.h"
#include "encode.h"
#include "unescape.h"

static char * get_extension(const char * url, char * fieldname);

/*
 * ldap_client - Given a URL, fetch the data from a single attribute.
 *
 * A sample URL is to fetch the cn attribute for user alpha is
 *    ldap://pebblebeach:3389/o=TestCentral?cn?sub?(uid=alpha)
 *
 * Using LDAP extensions one can what (if any) authentication is to be used.
 * Extensions are added after the search filter, separated by another "?".
 * The format of the extension is extension=value. Multiple extensions are
 * separated by commas. "Official" extensions do not need an x- prefix. Those
 * with an x- prefix are under consideration. We support both here.
 *
 * The following extensions are supported
 *  [x-]bindMechanism=<SASL-mechanism-name>
 *  [x-]bindName=<LDAPDN>
 *  [x-]bindCredentials=<password-or-other>
 *  [x-]bindTLSCertificateName=<cert nickname>
 *
 * NOTES:
 *   1. The bindName entry needs to be URL-escaped.
 *   2. The bindCredentials must be uuencoded. It is ok to have an = sign in the
 *      content of the password.
 *   3. In order to use ldaps client auth when the server is not in secure mode
 *      you need to set LDAPClientAuth on in magnus.conf. This will open the
 *      the security databases and authenticate the token(s).
 *
 * A sample URL is:
 *   ldap://localhost:3389/o=TestCentral?telephoneNumber?sub?(uid=alpha)?x-bindname=uid%3dalpha%2cou%3dPeople%2co%3dTestCentral,x-bindcredentials=YWxwaGE=
 *
 *
 * url: the source and attribute to fetch
 * timeout: time in seconds to wait for ldap search to complete
 */
void * ldap_client(const char *url, int timeout, int * len, int * errnum)
{
    LDAPURLDesc  * ludp = NULL;
    LDAP * ld = NULL;
    LDAPMessage * result = NULL;
    LDAPMessage * e = NULL;
    struct berval val_data; 
    struct berval **vals = NULL;
    void * data = NULL;
    int rv = 0;
    int i = 0;
    const int desiredVersion = LDAP_VERSION3;
    struct timeval ldtimeout;
    struct berval cred;
    struct berval *servcred;
    char * bindname = NULL;
    char * bindcredentials = NULL;
    char * bindmechanism = NULL;
    char * bindcertname = NULL;
    char * mechanism = NULL;

    uri_unescape_strict((char *)url, 1);

    if ((rv = ldap_url_parse(url, &ludp)) != 0) {
        switch(rv){
#ifdef MOZILLA_LDAP
            case LDAP_URL_ERR_NOTLDAP:
                *errnum = CL_URL_ERR_NOTLDAP;
                break;
            case LDAP_URL_ERR_NODN:
                *errnum = CL_URL_ERR_NODN;
                break;
#endif
            case LDAP_URL_ERR_BADSCOPE:
                *errnum = CL_URL_ERR_BADSCOPE;
                break;
            case LDAP_URL_ERR_MEM:
                *errnum = CL_URL_ERR_MEM;
                break;
            default:
                *errnum = CL_URL_ERR_UNKNOWN;
       }
       goto done;
    }
    
    if (ludp->lud_attrs == NULL) {
        *errnum = CL_LDAP_NO_ATTRS;
        goto done;
    }

    for (i = 0; ludp->lud_attrs[ i ] != NULL; ++i);

    if (i > 1) {
        *errnum = CL_LDAP_TOO_MANY_ATTRS;
        goto done;
    }

#ifdef MOZILLA_LDAP
    if ((ludp->lud_options & LDAP_URL_OPT_SECURE) != 0) {
            ld = ldapssl_init(ludp->lud_host, ludp->lud_port, 1 /* secure */ );
            if (ld && (ldapssl_set_option(ld, SSL_NO_CACHE, PR_TRUE) != 0))
                ld = NULL;
    } else
#endif
        ld = ldap_init(ludp->lud_host, ludp->lud_port);

    if (ld == NULL) {
        *errnum = CL_LDAP_CONNECT_FAILED;
        goto done;
    }

    // set LDAP v3
    rv = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, (void *)&desiredVersion);

    // get the extension for bindMechanism, default to SIMPLE
    bindmechanism = get_extension(url, "bindmechanism");

    // initialize the credentials
    cred.bv_val = NULL;
    cred.bv_len = 0;

    // see if they are using simple authentication, otherwise we bind
    // anonymously
    if ((bindname = get_extension(url, "bindname")) != NULL) {
        bindcredentials = get_extension(url, "bindcredentials");
        if (!bindcredentials) {
            *errnum = CL_LDAP_INVALID_CRED;
            goto done;
        }

        bindcredentials = do_uudecode(bindcredentials);
        uri_unescape_strict(bindname, 1);

        cred.bv_val = bindcredentials;
        cred.bv_len = strlen(bindcredentials);
#ifdef MOZILLA_LDAP
    } else if ((bindcertname = get_extension(url, "bindTLSCertificateName")) 
               != NULL) {
        uri_unescape_strict(bindcertname, 1);
        if (ldapssl_enable_clientauth(ld, NULL, "", (char *)bindcertname) == LDAP_SUCCESS) {
            if (!bindmechanism)
                mechanism = LDAP_SASL_EXTERNAL;
        } else {
            *errnum = CL_LDAP_CLAUTH_INIT;
            goto done;
        }
#endif
    }

    if (!bindmechanism)
        mechanism = LDAP_SASL_SIMPLE;
    else
        mechanism = bindmechanism;

    if (ldap_sasl_bind_s(ld, bindname, mechanism, &cred, NULL, 
                         NULL, &servcred) != LDAP_SUCCESS)
    {
        if (bindname || bindcertname)
            *errnum = CL_LDAP_AUTHBIND_FAILED;
        else
            *errnum = CL_LDAP_BIND_FAILED;
        goto done;
    }
    if (!bindmechanism)
        bindmechanism = LDAP_SASL_SIMPLE;

    ldtimeout.tv_sec = timeout;
    ldtimeout.tv_usec = 0;

    if (ldap_search_st(ld, ludp->lud_dn, ludp->lud_scope, ludp->lud_filter, ludp->lud_attrs, 0, &ldtimeout, &result) != LDAP_SUCCESS)
    {
        *errnum = CL_LDAP_SEARCH_FAILED;
        goto done;
    }

    /* Quit if not exactly 1 match */
    if (ldap_count_entries(ld, result) != 1)
    {
        *errnum = CL_LDAP_NOT_ONE_ENTRY;
        goto done;
    }

    if ((e = ldap_first_entry(ld, result)) == NULL)
    {
        *errnum = CL_LDAP_ATTR_GET_FAILED;
        goto done;
    }

    /* Get the attribute requested */
    if ((vals = ldap_get_values_len(ld, e, ludp->lud_attrs[0])) != NULL)
    {
       val_data = *vals[0]; 
       data = (void *)malloc(val_data.bv_len);
       *len = val_data.bv_len; // return the length
       memcpy(data, val_data.bv_val, val_data.bv_len);
    }

done:
    if (ludp)
        ldap_free_urldesc(ludp);
    if (vals)
        ldap_value_free_len(vals);
    if (result)
        ldap_msgfree(result);
    if (ld)
        ldap_unbind(ld);
    if (bindname)
        PL_strfree(bindname);
    if (bindcredentials)
        PL_strfree(bindcredentials);
    if (bindmechanism)
        PL_strfree(bindmechanism);
    if (bindcertname)
        PL_strfree(bindcertname);

    return data;
}

/* Get an LDAP URL extension. These are defined after the 4th ? in the URL.
 * We should use x- names but we're working on formalizing these so I'm
 * allowing either the x- or the non x- versions. The caller needs to free
 * the returned value.
 */
char * get_extension(const char * url, char * fieldname)
{
    char * workurl, *s, *f, *v;
    int fieldcount = 0;
    char * xext = 0;
    char * rv = NULL;
    int l = 0;

    workurl = PL_strdup(url);
    s = workurl;

    while (*s && fieldcount < 4) {
        if (*s++ == '?')
            fieldcount++;
    }

    if (fieldcount != 4) {
        // There are no extensions
        PL_strfree(workurl);
        return NULL;
    }

    // Try with X- too
    l = strlen(s);
    if (l == 0)
        goto done;
    xext = (char *)PR_Malloc(l + 3);
    PL_strcpy(xext, "x-");
    PL_strcat(xext, fieldname);

    // extensions are separated by a comma
    while ((f = (char *)strchr(s, ',')) != NULL) {
        *f++ = '\0';

        if (!PL_strncasecmp(fieldname, s, strlen(fieldname)) ||
            !PL_strncasecmp(xext, s, strlen(xext))) 
        {
            if ((v = (char *)strchr(s, '=')) != NULL) {
                *v++ = '\0';
                rv = PL_strdup(v);
                goto done;
            }
        }
        s = f;
    }

    // do the last one too
    if (!PL_strncasecmp(fieldname, s, strlen(fieldname)) ||
        !PL_strncasecmp(xext, s, strlen(xext))) 
    {
        if ((v = (char *)strchr(s, '=')) != NULL) {
            *v++ = '\0';
            rv = PL_strdup(v);
            goto done;
        }
    }

done:

    if (workurl)
        PL_strfree(workurl);
 
    if (xext)
        PR_Free(xext);

    return rv;
}
