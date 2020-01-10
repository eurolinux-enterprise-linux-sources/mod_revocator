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
extern "C" {
#include "pkcs11layer.h"
}

#if 0
extern "C" CK_C_INITIALIZE_ARGS_PTR nssstub_pInitArgs = NULL;
CK_C_INITIALIZE_ARGS nssstub_initArgs;
extern "C" NSSArena *nssstub_arena = NULL;
extern "C" CryptokiLockingState nssstub_LockingState = SingleThreaded;
#endif
CK_C_INITIALIZE_ARGS_PTR nssstub_pInitArgs = NULL;
CK_C_INITIALIZE_ARGS nssstub_initArgs;
NSSArena *nssstub_arena = NULL;
CryptokiLockingState nssstub_LockingState = SingleThreaded;

extern "C" PR_IMPLEMENT(CK_RV)
nssSetLockArgs(CK_C_INITIALIZE_ARGS_PTR pInitArgs, CryptokiLockingState* returned)
{
    if (nssstub_pInitArgs == NULL) {
	nssstub_initArgs = *pInitArgs;
        nssstub_pInitArgs = &nssstub_initArgs;
	/* nssstub_arena = NSSArena_Create(); */
    }
    *returned = nssstub_LockingState;
    return CKR_OK;
}
