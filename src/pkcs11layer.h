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

    PKCS#11 layer for revocation engine

    Julien Pierre
    Netscape Communications
    
    history
    
    13 Feb 2002 - start
        
*/

#ifndef __REVOCATIONPKCS11__
#define __REVOCATIONPKCS11__

#ifdef __cplusplus

class CRLInstance;

class UsageCount
{
public:
    UsageCount();
    ~UsageCount();
};

extern "C"
{

#endif

#include "nssckmdt.h"
#include "nssckfw.h"

/*
 * I'm including this for access to the arena functions.
 * Looks like we should publish that API.
 */
#ifndef BASE_H
#include "base.h"
#endif /* BASE_H */

/*
 * This is where the Netscape extensions live, at least for now.
 */
#ifndef CKT_H
#include "ckt.h"
#endif /* CKT_H */

NSS_EXTERN_DATA const CK_VERSION   revocator_CryptokiVersion;
NSS_EXTERN_DATA const NSSUTF8 *    revocator_ManufacturerID;
NSS_EXTERN_DATA const NSSUTF8 *    revocator_LibraryDescription;
NSS_EXTERN_DATA const CK_VERSION   revocator_LibraryVersion;
NSS_EXTERN_DATA const NSSUTF8 *    revocator_SlotDescription;
NSS_EXTERN_DATA const CK_VERSION   revocator_HardwareVersion;
NSS_EXTERN_DATA const CK_VERSION   revocator_FirmwareVersion;
NSS_EXTERN_DATA const NSSUTF8 *    revocator_TokenLabel;
NSS_EXTERN_DATA const NSSUTF8 *    revocator_TokenModel;
NSS_EXTERN_DATA const NSSUTF8 *    revocator_TokenSerialNumber;

NSS_EXTERN_DATA const NSSCKMDInstance revocator_mdInstance;
NSS_EXTERN_DATA const NSSCKMDSlot     revocator_mdSlot;
NSS_EXTERN_DATA const NSSCKMDToken    revocator_mdToken;
NSS_EXTERN_DATA const NSSCKMDObject   revocator_prototype_mdObject;


NSS_EXTERN NSSCKMDSession *
revocator_CreateSession
(
  NSSCKFWSession *fwSession,
  CK_RV *pError
);

NSS_EXTERN NSSCKMDFindObjects *
revocator_FindObjectsInit
(
  NSSCKFWSession *fwSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount,
  CK_RV *pError
);

NSS_EXTERN NSSCKMDObject *
revocator_CreateMDObject
(
  NSSArena *arena,
  CRLInstance* io,
  CK_RV *pError
);

PRBool RevocatorInitialized();

CK_BBOOL revocator_match(CK_ATTRIBUTE_PTR pTemplate,
                         CK_ULONG ulAttributeCount, CRLInstance* o);

#ifdef __cplusplus

}

#endif

#endif

