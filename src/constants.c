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
 * revocator/constants.c
 *
 * Identification and other constants, all collected here in one place.
 */

#ifndef NSSBASET_H
#include "nssbaset.h"
#endif /* NSSBASET_H */

#ifndef NSSCKT_H
#include "nssckt.h"
#endif /* NSSCKT_H */

NSS_IMPLEMENT_DATA const CK_VERSION
revocator_CryptokiVersion = { 2, 1 };

NSS_IMPLEMENT_DATA const NSSUTF8 *
revocator_ManufacturerID = (NSSUTF8 *) "Netscape Communications Corp.";

NSS_IMPLEMENT_DATA const NSSUTF8 *
revocator_LibraryDescription = (NSSUTF8 *) "Revocator Cryptoki Module";

NSS_IMPLEMENT_DATA const CK_VERSION
revocator_LibraryVersion = { 1, 0 };

NSS_IMPLEMENT_DATA const NSSUTF8 *
revocator_SlotDescription = (NSSUTF8 *) "Revocator Slot";

NSS_IMPLEMENT_DATA const CK_VERSION
revocator_HardwareVersion = { 1, 0 };

NSS_IMPLEMENT_DATA const CK_VERSION
revocator_FirmwareVersion = { 1, 0 };

NSS_IMPLEMENT_DATA const NSSUTF8 *
revocator_TokenLabel = (NSSUTF8 *) "Revocator Token";

NSS_IMPLEMENT_DATA const NSSUTF8 *
revocator_TokenModel = (NSSUTF8 *) "1";

/* should this be e.g. the certdata.txt RCS revision number? */
NSS_IMPLEMENT_DATA const NSSUTF8 *
revocator_TokenSerialNumber = (NSSUTF8 *) "1";

