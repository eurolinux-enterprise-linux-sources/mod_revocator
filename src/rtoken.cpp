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
extern "C"
{
#include "pkcs11layer.h"
}

/*
 * revocator/token.c
 *
 * This file implements the NSSCKMDToken object for the
 * "revocator objects" cryptoki module.
 */

extern "C" NSSUTF8 *
revocator_mdToken_GetLabel
(
  NSSCKMDToken *mdToken,
  NSSCKFWToken *fwToken,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  CK_RV *pError
)
{
  return (NSSUTF8 *)revocator_TokenLabel;
}

extern "C" NSSUTF8 *
revocator_mdToken_GetManufacturerID
(
  NSSCKMDToken *mdToken,
  NSSCKFWToken *fwToken,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  CK_RV *pError
)
{
  return (NSSUTF8 *)revocator_ManufacturerID;
}

extern "C" NSSUTF8 *
revocator_mdToken_GetModel
(
  NSSCKMDToken *mdToken,
  NSSCKFWToken *fwToken,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  CK_RV *pError
)
{
  return (NSSUTF8 *)revocator_TokenModel;
}

extern "C" NSSUTF8 *
revocator_mdToken_GetSerialNumber
(
  NSSCKMDToken *mdToken,
  NSSCKFWToken *fwToken,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  CK_RV *pError
)
{
  return (NSSUTF8 *)revocator_TokenSerialNumber;
}

extern "C" CK_BBOOL
revocator_mdToken_GetIsWriteProtected
(
  NSSCKMDToken *mdToken,
  NSSCKFWToken *fwToken,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance
)
{
  return CK_TRUE;
}

extern "C" CK_VERSION
revocator_mdToken_GetHardwareVersion
(
  NSSCKMDToken *mdToken,
  NSSCKFWToken *fwToken,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance
)
{
  return revocator_HardwareVersion;
}

extern "C" CK_VERSION
revocator_mdToken_GetFirmwareVersion
(
  NSSCKMDToken *mdToken,
  NSSCKFWToken *fwToken,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance
)
{
  return revocator_FirmwareVersion;
}

extern "C" NSSCKMDSession *
revocator_mdToken_OpenSession
(
  NSSCKMDToken *mdToken,
  NSSCKFWToken *fwToken,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  NSSCKFWSession *fwSession,
  CK_BBOOL rw,
  CK_RV *pError
)
{
  return revocator_CreateSession(fwSession, pError);
}

extern "C" NSS_IMPLEMENT_DATA const NSSCKMDToken
revocator_mdToken = {
  (void *)NULL, /* etc */
  NULL, /* Setup */
  NULL, /* Invalidate */
  NULL, /* InitToken -- default errs */
  revocator_mdToken_GetLabel,
  revocator_mdToken_GetManufacturerID,
  revocator_mdToken_GetModel,
  revocator_mdToken_GetSerialNumber,
  NULL, /* GetHasRNG -- default is false */
  revocator_mdToken_GetIsWriteProtected,
  NULL, /* GetLoginRequired -- default is false */
  NULL, /* GetUserPinInitialized -- default is false */
  NULL, /* GetRestoreKeyNotNeeded -- irrelevant */
  NULL, /* GetHasClockOnToken -- default is false */
  NULL, /* GetHasProtectedAuthenticationPath -- default is false */
  NULL, /* GetSupportsDualCryptoOperations -- default is false */
  NULL, /* GetMaxSessionCount -- default is CK_UNAVAILABLE_INFORMATION */
  NULL, /* GetMaxRwSessionCount -- default is CK_UNAVAILABLE_INFORMATION */
  NULL, /* GetMaxPinLen -- irrelevant */
  NULL, /* GetMinPinLen -- irrelevant */
  NULL, /* GetTotalPublicMemory -- default is CK_UNAVAILABLE_INFORMATION */
  NULL, /* GetFreePublicMemory -- default is CK_UNAVAILABLE_INFORMATION */
  NULL, /* GetTotalPrivateMemory -- default is CK_UNAVAILABLE_INFORMATION */
  NULL, /* GetFreePrivateMemory -- default is CK_UNAVAILABLE_INFORMATION */
  revocator_mdToken_GetHardwareVersion,
  revocator_mdToken_GetFirmwareVersion,
  NULL, /* GetUTCTime -- no clock */
  revocator_mdToken_OpenSession,
  NULL, /* GetMechanismCount -- default is zero */
  NULL, /* GetMechanismTypes -- irrelevant */
  NULL, /* GetMechanism -- irrelevant */
  (void *)NULL /* null terminator */
};
