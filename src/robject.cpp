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
 * revocator/object.cpp
 *
 * This file implements the NSSCKMDObject object for the
 * "builtin objects" cryptoki module.
 */

/*
    * Finalize - not needed
    * Destroy - CKR_SESSION_READ_ONLY
    * IsTokenObject - CK_TRUE
    * GetAttributeCount
    * GetAttributeTypes
    * GetAttributeSize
    * GetAttribute
    * SetAttribute - unneeded
    * GetObjectSize
*/

// default values for the first 6 fields

const CK_OBJECT_CLASS RevocatorClass = CKO_NETSCAPE_CRL; // all revocator objects are CRLs

const CK_BBOOL RevocatorTokenObject = PR_TRUE; // all revocator objects are token objects

const CK_BBOOL RevocatorPrivate = PR_FALSE; // all revocator objects are public

const char* RevocatorLabel = NULL; // no revocator objects have a label

const CK_BBOOL RevocatorModifiable = PR_TRUE; // all revocator objects are modifiable

const CK_BBOOL RevocatorIsKRL = PR_FALSE; // no revocator objects are KRLs

const PRUint32 revocatorAttributeCount = 9;

const CK_ATTRIBUTE_TYPE LastConstAttribute = CKA_NETSCAPE_KRL;

typedef struct RevocatorFixedAttributes
{
    CK_ATTRIBUTE attribute;
    NSSItem item;
};

const RevocatorFixedAttributes RevocatorAttributes [revocatorAttributeCount] =
{
    // hardcoded to 9 attribute types :
    // 6 fixed-value fields
    {
        // class
        { CKA_CLASS, (CK_VOID_PTR) &RevocatorClass, sizeof(RevocatorClass) },
        { (void*) &RevocatorClass, sizeof(RevocatorClass) }
    },

    {
        // token
        { CKA_TOKEN, (CK_VOID_PTR) &RevocatorTokenObject, sizeof(RevocatorTokenObject) },
        { (void*) &RevocatorTokenObject, sizeof(RevocatorTokenObject) }
    },
    {
        // private
        { CKA_PRIVATE, (CK_VOID_PTR) &RevocatorPrivate, sizeof(RevocatorPrivate) },
        { (void*) &RevocatorPrivate, sizeof(RevocatorPrivate) }
    },
    {
        // label
        { CKA_LABEL, (CK_VOID_PTR) &RevocatorLabel, sizeof(RevocatorLabel) },
        { (void*) &RevocatorLabel, sizeof(RevocatorLabel) }
    },
    {
        // modifiable
        { CKA_MODIFIABLE, (CK_VOID_PTR) &RevocatorModifiable, sizeof(RevocatorModifiable) },
        { (void*) &RevocatorModifiable, sizeof(RevocatorModifiable) }
    },
    {
        // is KRL
        { CKA_NETSCAPE_KRL, (CK_VOID_PTR) &RevocatorIsKRL, sizeof(RevocatorIsKRL) },
        { (void*) &RevocatorIsKRL, sizeof(RevocatorIsKRL) }
    },
    {
        // DER CRL
        { CKA_VALUE, (CK_VOID_PTR) NULL, 0 },
        { (void*) NULL, 0 },
    },
    {
        // DER subject
        { CKA_SUBJECT, (CK_VOID_PTR) NULL, 0 }, 
        { (void*) NULL, 0 }, 
    },
    {
        // URL
        { CKA_NETSCAPE_URL,  (CK_VOID_PTR) NULL, 0 },
        { (void*) NULL, 0 }
    }
};


extern "C" CK_RV
revocator_mdObject_Destroy
(
    NSSCKMDObject *mdObject,
    NSSCKFWObject *fwObject,
    NSSCKMDSession *mdSession,
    NSSCKFWSession *fwSession,
    NSSCKMDToken *mdToken,
    NSSCKFWToken *fwToken,
    NSSCKMDInstance *mdInstance,
    NSSCKFWInstance *fwInstance
)
{
  return CKR_SESSION_READ_ONLY;
}

extern "C" CK_BBOOL
revocator_mdObject_IsTokenObject
(
    NSSCKMDObject *mdObject,
    NSSCKFWObject *fwObject,
    NSSCKMDSession *mdSession,
    NSSCKFWSession *fwSession,
    NSSCKMDToken *mdToken,
    NSSCKFWToken *fwToken,
    NSSCKMDInstance *mdInstance,
    NSSCKFWInstance *fwInstance
)
{
    return RevocatorTokenObject;
}

extern "C" CK_ULONG
revocator_mdObject_GetAttributeCount
(
    NSSCKMDObject *mdObject,
    NSSCKFWObject *fwObject,
    NSSCKMDSession *mdSession,
    NSSCKFWSession *fwSession,
    NSSCKMDToken *mdToken,
    NSSCKFWToken *fwToken,
    NSSCKMDInstance *mdInstance,
    NSSCKFWInstance *fwInstance,
    CK_RV *pError
)
{
    return revocatorAttributeCount;
}

extern "C" CK_RV
revocator_mdObject_GetAttributeTypes
(
    NSSCKMDObject *mdObject,
    NSSCKFWObject *fwObject,
    NSSCKMDSession *mdSession,
    NSSCKFWSession *fwSession,
    NSSCKMDToken *mdToken,
    NSSCKFWToken *fwToken,
    NSSCKMDInstance *mdInstance,
    NSSCKFWInstance *fwInstance,
    CK_ATTRIBUTE_TYPE_PTR typeArray,
    CK_ULONG ulCount
)
{
    PRUint32 i;
    // hardcoded to 9 types

    if( revocatorAttributeCount < ulCount )
    {
        return CKR_BUFFER_TOO_SMALL;
    }
    else
    if (revocatorAttributeCount != ulCount)
    {
        return CKR_DEVICE_ERROR;
    }

    for( i = 0; i < revocatorAttributeCount; i++ )
    {
        typeArray[i] = RevocatorAttributes[i].attribute.type;
    }

    return CKR_OK;
}

extern "C" CK_ULONG
revocator_mdObject_GetAttributeSize
(
    NSSCKMDObject *mdObject,
    NSSCKFWObject *fwObject,
    NSSCKMDSession *mdSession,
    NSSCKFWSession *fwSession,
    NSSCKMDToken *mdToken,
    NSSCKFWToken *fwToken,
    NSSCKMDInstance *mdInstance,
    NSSCKFWInstance *fwInstance,
    CK_ATTRIBUTE_TYPE attribute,
    CK_RV *pError
)
{
    CK_ULONG i = 0;
    CK_ATTRIBUTE_TYPE attrtype = 0;
    do
    {
        attrtype = RevocatorAttributes[i].attribute.type;
        if (attrtype == attribute)
        {
            // hardcoded size for first 6 - return exact attribute size
            return RevocatorAttributes[i].attribute.ulValueLen;
        }
        i++;
    } while ( attrtype != LastConstAttribute );

    PRBool matchattr = PR_FALSE;
    do
    {
        attrtype = RevocatorAttributes[i].attribute.type;
        if ((attrtype = attribute))
        {
            matchattr = PR_TRUE;
            break;
        }
        i++;
    } while (i<revocatorAttributeCount);

    if (!matchattr)
    {
        // unknown attribute
        *pError = CKR_ATTRIBUTE_TYPE_INVALID;
        return 0;
    }

    // variable size for last 3 attributes
    // we need to return a size slightly larger than the real one, in case
    // the CRL increases in size between the time that NSS gets the attribute size
    // and the attribute value. Otherwise the CRL fetch will fail, and some
    // unauthorized users might be let through ...
    CRLInstance* io = (CRLInstance *)mdObject->etc;
    PR_ASSERT(io);
    if (!io)
    {
        // invalid object
        *pError = CKR_OBJECT_HANDLE_INVALID;
        return 0;
    }
    const PRInt32 fudgefactor = 0;
    switch (attribute)
    {
        case CKA_VALUE:
            {
                // return binary DER of the CRL. This will change,
                // and may even grow between this call and the GetAttribute call
                PRInt32 derlen = 0;

                io->acquire();
                const SECItem* dercrl = io->getDERCRL();
                if (dercrl)
                {
                    derlen = dercrl->len;
                }
                io->release();

                return fudgefactor + derlen;
            }
            break;

        case CKA_SUBJECT:
            {
                // return binary DER subject of the CRL. This shouldn't change,
                // but it may if the CA modifies its configuration (very rare)
                // or in case of DNS attack, which should be detected way
                // before we got here by the signature check
                PRInt32 subjlen = 0;

                io->acquire();
                const SECItem* subject = io->getDERSubject();
                if (subject)
                {
                    subjlen = subject->len;
                }
                io->release();

                return fudgefactor + subjlen;
            }
            break;

        case CKA_NETSCAPE_URL:
            {
                // return URL of the CRL. This will never change
                // but lock anyway ...
                PRInt32 urllen = 0;
                io->acquire();
                const char* url = io->getURL();
                if (url)
                {
                    urllen = strlen(url);
                }
                io->release();
                return urllen;
            }
            break;

        default:
            {
                // we should not ever get here
                PR_ASSERT(0);
                *pError = CKR_ATTRIBUTE_TYPE_INVALID;
                return 0;
            }
    }
}

NSSItem* MakeItem(NSSArena *arena, const CK_ULONG len, const CK_VOID_PTR value)
{
    NSSItem* item = (NSSItem*) PR_Malloc(sizeof(NSSItem));
    PR_ASSERT(item);
    if (!item)
    {
        return NULL;
    }
    item->size = len;
    item->data = PR_Malloc(len);
    PR_ASSERT(item->data);
    if (!item->data)
    {
        PR_Free(item);
        return NULL;
    }
    memcpy(item->data, value, len);
    return item;
}

CK_RV FreeItem(NSSItem* item)
{
    PR_ASSERT(item);
    if (!item)
    {
        return CKR_HOST_MEMORY;
    }
    PR_ASSERT(item->size);
    PR_ASSERT(item->data);
    PR_Free(item->data);
    item->data = NULL;
    item->size = 0;
    PR_Free(item);
    return CKR_OK;
}

NSSCKFWItem revocator_GetAttribute(CRLInstance* io, CK_ATTRIBUTE_TYPE attribute,
                                   CK_RV* pError)
{
    CK_ULONG i = 0;
    CK_ATTRIBUTE_TYPE attrtype = 0;
    NSSCKFWItem newitem;
    newitem.needsFreeing = PR_FALSE;
    newitem.item = (NSSItem*) NULL;

    do
    {
        attrtype = RevocatorAttributes[i].attribute.type;
        if (attrtype == attribute)
        {
            // hardcoded size for first 6 - return hardcoded attribute value
            newitem.item = (NSSItem*)&RevocatorAttributes[i].item;
            return newitem;
        }
        i++;
    } while ( attrtype != LastConstAttribute );

    PRBool matchattr = PR_FALSE;
    do
    {
        attrtype = RevocatorAttributes[i].attribute.type;
        if ((attrtype = attribute))
        {
            matchattr = PR_TRUE;
            break;
        }
        i++;
    } while (i<revocatorAttributeCount);

    if (!matchattr)
    {
        // unknown attribute
        *pError = CKR_ATTRIBUTE_TYPE_INVALID;
        return newitem;
    }

    switch (attribute)
    {
        case CKA_SUBJECT:
        case CKA_VALUE:
        case CKA_NETSCAPE_URL:
            {
                // return binary DER of the CRL. This will change,
                // and may even grow between this call and the GetAttribute call
                NSSItem* newnssitem = NULL;
                io->acquire();
                const SECItem* newsecitem = NULL;
                void* data = NULL;
                PRInt32 len = 0;
                
                switch (attribute)
                {
                    case CKA_VALUE :
                        newsecitem = io->getDERCRL();
                        break;

                    case CKA_SUBJECT :
                        newsecitem = io->getDERSubject();
                        break;

                    case CKA_NETSCAPE_URL :
                        {
                            const char* url = io->getURL();
                            if (url)
                            {
                                len = strlen(url);
                                data = (void*) url;
                            }
                            break;
                        }
                    default:
                        PR_ASSERT(0); // we definitely should not get here
                }
                if (newsecitem)
                {
                    data = newsecitem->data;
                    len = newsecitem->len;
                }
                newnssitem = MakeItem(NULL, len, data);
                if (newnssitem)
                {
                    newitem.item = newnssitem;
                    newitem.needsFreeing = PR_TRUE;
                }
                io->release();

                return newitem;
            }
            break;

        default:
            {
                // we should not ever get here
                PR_ASSERT(0);
                *pError = CKR_ATTRIBUTE_TYPE_INVALID;
                return newitem;
            }
    }
}

extern "C" NSSCKFWItem
revocator_mdObject_GetAttribute
(
    NSSCKMDObject *mdObject,
    NSSCKFWObject *fwObject,
    NSSCKMDSession *mdSession,
    NSSCKFWSession *fwSession,
    NSSCKMDToken *mdToken,
    NSSCKFWToken *fwToken,
    NSSCKMDInstance *mdInstance,
    NSSCKFWInstance *fwInstance,
    CK_ATTRIBUTE_TYPE attribute,
    CK_RV* pError
)
{
    NSSCKFWItem mdItem;
    mdItem.needsFreeing = PR_FALSE;
    mdItem.item = (NSSItem*) NULL;
    // variable size for last 3 attributes . We return an NSSItem
    // with the actual data size
    CRLInstance* io = (CRLInstance *)mdObject->etc;
    PR_ASSERT(io);
    if (!io)
    {
        // invalid object
        *pError = CKR_OBJECT_HANDLE_INVALID;
        return mdItem;
    }
    mdItem = revocator_GetAttribute(io, attribute, pError);
    return mdItem;
}

extern "C" CK_RV
revocator_mdObject_FreeAttribute
(
    NSSCKFWItem * item
)
{
    PR_ASSERT(item);
    PR_ASSERT(item->item);
    if (!item || !item->item)
    {
        return CKR_HOST_MEMORY;
    }
    CK_RV rv = FreeItem(item->item);
    item->item = NULL;
    return rv;
}

/*

extern "C" CK_ULONG
revocator_mdObject_GetObjectSize
(
  NSSCKMDObject *mdObject,
  NSSCKFWObject *fwObject,
  NSSCKMDSession *mdSession,
  NSSCKFWSession *fwSession,
  NSSCKMDToken *mdToken,
  NSSCKFWToken *fwToken,
  NSSCKMDInstance *mdInstance,
  NSSCKFWInstance *fwInstance,
  CK_RV *pError
)
{
    // do not implement 
    CRLInstance* io = (revocatorInternalObject *)mdObject->etc;
    CK_ULONG i;
    CK_ULONG rv = sizeof(CK_ULONG);

    for( i = 0; i < io->n; i++ )
    {
        rv += sizeof(CK_ATTRIBUTE_TYPE) + sizeof(NSSItem) + io->items[i].size;
    }

    return rv;
}

*/

extern "C" CK_BBOOL
revocator_attrmatch
(
    CK_ATTRIBUTE_PTR a,
    const NSSItem* b
)
{
    PRBool prb;

    if( a->ulValueLen != b->size )
    {
        return CK_FALSE;
    }

    prb = nsslibc_memequal(a->pValue, b->data, b->size, (PRStatus *)NULL);

    if( PR_TRUE == prb )
    {
        return CK_TRUE;
    }
    else
    {
        return CK_FALSE;
    }
}

extern "C" CK_BBOOL
revocator_match
(
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CRLInstance* o
)
{
    CK_ULONG i;

    for( i = 0; i < ulAttributeCount; i++ )
    {
        CK_ULONG j;

        for( j = 0; j < revocatorAttributeCount; j++ )
        {
            if( RevocatorAttributes[j].attribute.type == pTemplate[i].type )
            {
                CK_RV err;
                NSSCKFWItem attr = revocator_GetAttribute(o, pTemplate[i].type, &err);
                PR_ASSERT(attr.item);
                if (!attr.item)
                {
                    continue;
                }
                if( CK_FALSE == revocator_attrmatch(&pTemplate[i], attr.item) )
                {
                    return CK_FALSE;
                }
                else
                {
                    break;
                }
            }
        }

        if( j == revocatorAttributeCount )
        {
            // Loop ran to the end: no matching attribute
            return CK_FALSE;
        }
    }

    // Every attribute passed
    return CK_TRUE;
}

extern "C" const NSSCKMDObject
revocator_prototype_mdObject = {
  (void *)NULL, // etc
  NULL, // Finalize
  revocator_mdObject_Destroy,
  revocator_mdObject_IsTokenObject,
  revocator_mdObject_GetAttributeCount,
  revocator_mdObject_GetAttributeTypes,
  revocator_mdObject_GetAttributeSize,
  revocator_mdObject_GetAttribute,
  revocator_mdObject_FreeAttribute,
  NULL, // SetAttribute
  NULL, //revocator_mdObject_GetObjectSize,
  (void *)NULL // null terminator
};

NSS_IMPLEMENT NSSCKMDObject*
revocator_CreateMDObject
(
  NSSArena *arena,
  CRLInstance *io,
  CK_RV *pError
)
{
    // everything is already done for us in the constructor
    PR_ASSERT(io);
    if (io)
    {
        return io->getMdObject();
    }
    else
    {
        return NULL;
    }
}

