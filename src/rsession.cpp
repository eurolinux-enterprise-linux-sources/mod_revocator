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
#include "pkcs11layer.h"
#include "revocation.h"
#include "crlmanager.h"

/*
 * rsession.cpp
 *
 * This file implements the NSSCKMDSession object for the 
 * "revocator" cryptoki module.
 */

extern "C" NSSCKMDFindObjects *
revocator_mdSession_FindObjectsInit
(
  NSSCKMDSession *mdSession,
  NSSCKFWSession *fwSession,
  NSSCKMDToken *mdToken,
  NSSCKFWToken *fwToken,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount,
  CK_RV *pError
)
{
    // we check that the CRLManager has been initialized
    if (!RevocatorInitialized())
    {
        return NULL;
    }
    // now we really have CRLs, search here 
    return revocator_FindObjectsInit(fwSession, pTemplate, ulAttributeCount, pError);
}

NSS_IMPLEMENT NSSCKMDSession *
revocator_CreateSession
(
  NSSCKFWSession *fwSession,
  CK_RV *pError
)
{
  NSSArena *arena;
  NSSCKMDSession *rv;

  arena = NSSCKFWSession_GetArena(fwSession, pError);
  if( (NSSArena *)NULL == arena ) {
    return (NSSCKMDSession *)NULL;
  }

  rv = nss_ZNEW(arena, NSSCKMDSession);
  if( (NSSCKMDSession *)NULL == rv ) {
    *pError = CKR_HOST_MEMORY;
    return (NSSCKMDSession *)NULL;
  }

  /* 
   * rv was zeroed when allocated, so we only 
   * need to set the non-zero members.
   */

  rv->FindObjectsInit = revocator_mdSession_FindObjectsInit;

  return rv;
}
