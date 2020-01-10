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
// ripped off from lib/base

/*
 * The URLs passing into the revocator are URL-encoded because we need to
 * use semi-colon as the separator character in magnus.conf.
 *
 * For LDAP URLs we want to decode everything up to the 4th ?. After that we
 * need to be a bit pickier about what we decode, basically just commas and
 * equals.
 */
int uri_unescape_strict(char *s, int ldap)
{
    char *t, *u, t1, t2;
    int fieldcount = 0;
    int stop = 0;

    for(t = s, u = s; *t; ++t, ++u) {
        if (!stop && *t == '%') {
            t1 = t[1] & 0xdf; /* [a-f] -> [A-F] */
            if ((t1 < 'A' || t1 > 'F') && (t[1] < '0' || t[1] > '9'))
                return 0;

            t2 = t[2] & 0xdf; /* [a-f] -> [A-F] */
            if ((t2 < 'A' || t2 > 'F') && (t[2] < '0' || t[2] > '9'))
                return 0;

            *u = ((t[1] >= 'A' ? ((t[1] & 0xdf) - 'A')+10 : (t[1] - '0'))*16) +
                  (t[2] >= 'A' ? ((t[2] & 0xdf) - 'A')+10 : (t[2] - '0'));
            t += 2;
        }
        else if (u != t)
            *u = *t;

        // stop converting after 4 ?'s
        if ((ldap) && (*u == '?')) {
            fieldcount++; 
            if (fieldcount == 4)
                stop = 1;
        }
    }
    *u = *t;
    return 1;
}
