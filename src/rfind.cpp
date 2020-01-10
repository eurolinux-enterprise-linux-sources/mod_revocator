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
#include "crlmanager.h"

/*
 * rfind.cpp
 *
 * This file implements the NSSCKMDFindObjects object for the
 * "revocator" cryptoki module.
 */

struct revocatorFOStr
{
  NSSArena *arena;
  CK_ULONG n;
  CK_ULONG i;
  CRLInstance** objs;
};

extern "C" void
revocator_mdFindObjects_Final
(
  NSSCKMDFindObjects *mdFindObjects,
  NSSCKFWFindObjects *fwFindObjects,
  NSSCKMDSession *mdSession,
  NSSCKFWSession *fwSession,
  NSSCKMDToken *mdToken,
  NSSCKFWToken *fwToken,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance
)
{
  struct revocatorFOStr *fo = (struct revocatorFOStr *)mdFindObjects->etc;
  NSSArena *arena = fo->arena;

  nss_ZFreeIf(fo->objs);
  nss_ZFreeIf(fo);
  nss_ZFreeIf(mdFindObjects);
  if ((NSSArena *)NULL != arena) {
    NSSArena_Destroy(arena);
  }

  return;
}

extern "C" NSSCKMDObject *
revocator_mdFindObjects_Next
(
  NSSCKMDFindObjects *mdFindObjects,
  NSSCKFWFindObjects *fwFindObjects,
  NSSCKMDSession *mdSession,
  NSSCKFWSession *fwSession,
  NSSCKMDToken *mdToken,
  NSSCKFWToken *fwToken,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  NSSArena *arena,
  CK_RV *pError
)
{
  struct revocatorFOStr *fo = (struct revocatorFOStr *)mdFindObjects->etc;
  CRLInstance* io;

  if( fo->i == fo->n ) {
    *pError = CKR_OK;
    return (NSSCKMDObject *)NULL;
  }

  io = fo->objs[ fo->i ];
  fo->i++;

  return revocator_CreateMDObject(arena, io, pError);
}


NSS_IMPLEMENT NSSCKMDFindObjects *
revocator_FindObjectsInit
(
  NSSCKFWSession *fwSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount,
  CK_RV *pError
)
{
  NSSArena *arena;
  NSSCKMDFindObjects *rv = (NSSCKMDFindObjects *)NULL;
  struct revocatorFOStr *fo = (struct revocatorFOStr *)NULL;
  CRLInstance** temp = NULL;
  PRInt32 i;

  arena = NSSArena_Create();
  if( (NSSArena *)NULL == arena ) {
    goto loser;
  }

  rv = nss_ZNEW(arena, NSSCKMDFindObjects);
  if( (NSSCKMDFindObjects *)NULL == rv ) {
    *pError = CKR_HOST_MEMORY;
    goto loser;
  }

  fo = nss_ZNEW(arena, struct revocatorFOStr);
  if( (struct revocatorFOStr *)NULL == fo ) {
    *pError = CKR_HOST_MEMORY;
    goto loser;
  }

  fo->arena = arena;
  // fo->n and fo->i are already zero

  rv->etc = (void *)fo;
  rv->Final = revocator_mdFindObjects_Final;
  rv->Next = revocator_mdFindObjects_Next;
  rv->null = (void *)NULL;

  PR_ASSERT(crlm);
  temp = nss_ZNEWARRAY((NSSArena *)NULL, CRLInstance*, 
                       crlm->getNumCrls());
  if( (CRLInstance **)NULL == temp ) {
    *pError = CKR_HOST_MEMORY;
    goto loser;
  }

  // XXX we should check the template for all constant attributes and abort
  // immediately if they don't match

  // we need to enumerate the CRLs here to do the match against the template
  for( i = 0; i < crlm->getNumCrls(); i++ )
  {
    CRLInstance* acrl = (CRLInstance *)crlm->getCrl(i);

    if( CK_TRUE == revocator_match(pTemplate, ulAttributeCount, acrl) ) {
      temp[ fo->n ] = acrl;
      fo->n++;
    }
  }

  fo->objs = nss_ZNEWARRAY(arena, CRLInstance *, fo->n);
  if( (CRLInstance **)NULL == fo->objs ) {
    *pError = CKR_HOST_MEMORY;
    goto loser;
  }

  (void)nsslibc_memcpy(fo->objs, temp, sizeof(CRLInstance *) * fo->n);
  nss_ZFreeIf(temp);
  temp = (CRLInstance **)NULL;

  return rv;

 loser:
  nss_ZFreeIf(temp);
  nss_ZFreeIf(fo);
  nss_ZFreeIf(rv);
  if ((NSSArena *)NULL != arena) {
     NSSArena_Destroy(arena);
  }
  return (NSSCKMDFindObjects *)NULL;
}

