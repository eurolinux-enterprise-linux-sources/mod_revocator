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

/*
 * revocator/slot.c
 *
 * This file implements the NSSCKMDSlot object for the
 * "revocator" cryptoki module.
 */

extern "C" NSSUTF8 *
revocator_mdSlot_GetSlotDescription
(
  NSSCKMDSlot *mdSlot,
  NSSCKFWSlot *fwSlot,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  CK_RV *pError
)
{
  return (NSSUTF8 *)revocator_SlotDescription;
}

extern "C" NSSUTF8 *
revocator_mdSlot_GetManufacturerID
(
  NSSCKMDSlot *mdSlot,
  NSSCKFWSlot *fwSlot,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  CK_RV *pError
)
{
  return (NSSUTF8 *)revocator_ManufacturerID;
}

extern "C" CK_VERSION
revocator_mdSlot_GetHardwareVersion
(
  NSSCKMDSlot *mdSlot,
  NSSCKFWSlot *fwSlot,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance
)
{
  return revocator_HardwareVersion;
}

extern "C" CK_VERSION
revocator_mdSlot_GetFirmwareVersion
(
  NSSCKMDSlot *mdSlot,
  NSSCKFWSlot *fwSlot,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance
)
{
  return revocator_FirmwareVersion;
}

extern "C" NSSCKMDToken *
revocator_mdSlot_GetToken
(
  NSSCKMDSlot *mdSlot,
  NSSCKFWSlot *fwSlot,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  CK_RV *pError
)
{
  return (NSSCKMDToken *)&revocator_mdToken;
}

extern "C" NSS_IMPLEMENT_DATA const NSSCKMDSlot
revocator_mdSlot = {
  (void *)NULL, /* etc */
  NULL, /* Initialize */
  NULL, /* Destroy */
  revocator_mdSlot_GetSlotDescription,
  revocator_mdSlot_GetManufacturerID,
  NULL, /* GetTokenPresent -- defaults to true */
  NULL, /* GetRemovableDevice -- defaults to false */
  NULL, /* GetHardwareSlot -- defaults to false */
  revocator_mdSlot_GetHardwareVersion,
  revocator_mdSlot_GetFirmwareVersion,
  revocator_mdSlot_GetToken,
  (void *)NULL /* null terminator */
};
