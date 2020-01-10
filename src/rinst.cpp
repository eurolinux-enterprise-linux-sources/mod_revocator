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
#include "revprivate.h"

#include "ckfwtm.h"
#include "ckfw.h"
#include "nssckfwt.h"
#include "cert.h"

// the following counter keeps track of all concurrent PKCS#11 calls
// to this module

static PRInt32 PKCS11Refcount = 0;
static PRLock* PKCS11reflock =  NULL;
static PRCondVar* PKCS11condvar = NULL;

static PRBool revocatorInitialized = PR_FALSE;

extern "C" PRBool RevocatorInitialized()
{
    return revocatorInitialized;
}

UsageCount :: UsageCount()
{
    if (!revocatorInitialized)
    {
        // we got called after the C_Finalize completed, or before
        // C_Initialize was called
        // do not increment the counter.
        // the PKCS#11 call that invoked this should check for
        // revocatorInitialized right after this stack object gets created,
        // and simply return
        return;
    }
    PR_Lock(PKCS11reflock);
    PKCS11Refcount++;
    PR_Unlock(PKCS11reflock);
}

UsageCount :: ~UsageCount()
{
    if (!revocatorInitialized)
    {
        // we got called after the C_Finalize completed, or before C_Initialize
        // do not decrement the counter.
        return;
    }

    PR_Lock(PKCS11reflock);
    PKCS11Refcount--;
    if (0 == PKCS11Refcount)
    {
        // no more PKCS#11 functions, notify C_Finalize to wake up
        PR_NotifyCondVar(PKCS11condvar);
    }
    PR_Unlock(PKCS11reflock);
}

// NSSCKMDInstance methods

extern "C" CK_RV revocatorInitialize(
    NSSCKMDInstance *mdInstance,                                    
    NSSCKFWInstance *fwInstance,
    NSSUTF8 *configurationData)

{
    if (revocatorInitialized)
    {
	return CKR_OK;
    }

    unsigned char* modparms = NULL;
    if (!fwInstance)
    {
        return CKR_ARGUMENTS_BAD;
    }
    CK_C_INITIALIZE_ARGS_PTR modArgs = NSSCKFWInstance_GetInitArgs(fwInstance);
    if (!modArgs)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (modArgs->LibraryParameters)
    {
        modparms = (unsigned char*)modArgs->LibraryParameters;
    }
    //  now check the configuration string
    crlm = new CRLManager((const char*)modparms);
    if (!crlm)
    {
        return CKR_HOST_MEMORY;
    }
    if (crlm->getStatus().hasFailed())
    {
        // call back with error
        const RevStatus rv = crlm->getStatus();
        NotifyFailure(NULL, NULL, &rv);
        delete(crlm);
        crlm = NULL;
        return CKR_ARGUMENTS_BAD;
    }

    // do the initial download of all CRLs
    RevStatus rvs = crlm->DownloadAllCRLs();

    if (!rvs.hasFailed())
    {
        rvs = crlm->StartEngine();
    }
    if (rvs.hasFailed())
    {
        delete(crlm);
        crlm = NULL;
        return CKR_DEVICE_ERROR;
    }

    PKCS11reflock = PR_NewLock();
    PKCS11condvar = PR_NewCondVar(PKCS11reflock);

    PR_AtomicSet(&revocatorInitialized, PR_TRUE);

    return CKR_OK;
}

extern "C" void revocatorFinalize(
    NSSCKMDInstance *mdInstance,
    NSSCKFWInstance *fwInstance)

{
    if (!revocatorInitialized)
    {
        return;
    }
    // wait for all outstanding PKCS#11 calls to this module to end
    PR_ASSERT(PKCS11reflock);
    PR_ASSERT(PKCS11condvar);
    if (PKCS11reflock && PKCS11condvar)
    {
        PR_Lock(PKCS11reflock);
        while (PKCS11Refcount>0)
        {
            PR_WaitCondVar(PKCS11condvar, PR_INTERVAL_NO_TIMEOUT);
        }
        PR_Unlock(PKCS11reflock);
    }
    // notify and wait for download thread to end
    PR_ASSERT(crlm);
    if (crlm)
    {
        crlm->stop();
    }
    PR_AtomicSet(&revocatorInitialized, PR_FALSE);
}

extern "C" CK_ULONG
revocator_mdInstance_GetNSlots
(
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  CK_RV *pError
)
{
    // we only have one slot
    return (CK_ULONG)1;
}

extern "C" CK_VERSION
revocator_mdInstance_GetCryptokiVersion
(
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance
)
{
  return revocator_CryptokiVersion;
}

extern "C" NSSUTF8 *
revocator_mdInstance_GetManufacturerID
(
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  CK_RV *pError
)
{
  return (NSSUTF8 *)revocator_ManufacturerID;
}

extern "C" NSSUTF8 *
revocator_mdInstance_GetLibraryDescription
(
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  CK_RV *pError
)
{
  return (NSSUTF8 *)revocator_LibraryDescription;
}

extern "C" CK_VERSION
revocator_mdInstance_GetLibraryVersion
(
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance
)
{
  return revocator_LibraryVersion;
}

extern "C" CK_RV
revocator_mdInstance_GetSlots
(
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  NSSCKMDSlot *slots[]
)
{
  slots[0] = (NSSCKMDSlot *)&revocator_mdSlot;
  return CKR_OK;
}

extern "C"
NSS_IMPLEMENT_DATA
const NSSCKMDInstance
revocator_mdInstance = {
  (void *)NULL, // etc
  revocatorInitialize, // Initialize
  revocatorFinalize, // Finalize
  revocator_mdInstance_GetNSlots,
  revocator_mdInstance_GetCryptokiVersion,
  revocator_mdInstance_GetManufacturerID,
  revocator_mdInstance_GetLibraryDescription,
  revocator_mdInstance_GetLibraryVersion,
  NULL, // ModuleHandlesSessionObjects -- defaults to false
  revocator_mdInstance_GetSlots,
  NULL, // WaitForSlotEvent
  (void *)NULL // null terminator
};

