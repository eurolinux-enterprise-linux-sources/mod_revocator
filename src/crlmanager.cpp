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

    CRL manager for revocation engine

    Julien Pierre
    Netscape Communications
    
    history
    
    17 Jan 2002 - start
        
*/

#include "nspr.h"
#include "revocation.h"
#include "download.h"
#include "crlmanager.h"
#include "client.h"
#include "secitem.h"
#include "rev_core.h"
#include "cert.h"
#include "certdb.h"
#include "revprivate.h"
#include "secder.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include <pk11func.h>

PR_IMPLEMENT_DATA(CRLManager* crlm = NULL);

const PRIntervalTime globaltimeout = PR_SecondsToInterval(30); // default 30s timeout
const PRTime oneminute = 60000000;

const char* OutOfMemory = OutOfMemory;

RevStatus CRLInstance :: DownloadCRL(const char* inurl,
                    const PRIntervalTime timeout, SECItem*& output) const
{
    RevStatus mystatus;
    PRInt32 len = 0 ;
    output = NULL;
    struct sembuf sb;

    /* lock the pipe */
    sb.sem_num = 0;
    sb.sem_op = -1;
    sb.sem_flg = SEM_UNDO;
    if (semop(crlm->semid, &sb, 1) == -1) {
        perror("semop reserve resource");
    }
    void* data = get_crl(crlm->infd, crlm->outfd, inurl, timeout, lastfetchtime, &len, mystatus);
    /* unlock the pipe */
    sb.sem_op = 1;
    if (semop(crlm->semid, &sb, 1) == -1) {
        perror("semop free resource id");
    }

    /* We have a special case. If we have an HTTP request and the server
     * response was 304 Not Modified we want to go ahead and continue as
     * if the request was successful. A CRL may be very large so this is
     * a good thing, we just have to jump through some hoops to achieve
     * it. First we log the fact that we tried and got a 304, then reset
     * things so in GetCRL() and update() we can detect this case.
     */
    if (mystatus.getError() == REV_ERROR_NOUPDATE_AVAILABLE) {
        reportError(mystatus); /* Report the error while we have it */
        mystatus.clearError();
        output = SECITEM_AllocItem(NULL, NULL, 1);
        output->len = 0;
        return mystatus;
    }
    if (!mystatus.hasFailed() && (!data || !len))
    {
        // the download did not fail, but we didn't get any data ...
        // this could be because of a bug in the client, or a zero-size object,
        // even though we successfully connected to the server
        mystatus.setDetailedError(REV_ERROR_MISSING_CRL_DATA,
                                  "No CRL data found on server");
    }
    if (mystatus.hasFailed())
    {
        return mystatus;
    }
    // make a SECItem out of the buffer returned by fetch_url
    output = SECITEM_AllocItem(NULL, NULL, len);
    PR_ASSERT(output);
    if (!output)
    {
        // allocation failed
        mystatus.setDetailedError(REV_ERROR_OUT_OF_MEMORY, OutOfMemory);
    }
    else
    {
        // copy the buffer
        memcpy(output->data, data, len);
    }
    // always free the data that was returned from the client
    free_url(data);

#if 0
    // use this debug code to make sure the client isn't corrupting the data
    // while downloading. This will write the binary DER CRL as provided by a
    // client to a file named after the REVLOG environment variable
    // corruption can cause subsequent failures and crashes in the ASN.1
    // decoder

    const char* fname = getenv("REVLOG");
    if (fname)
    {
        PRFileDesc* logfd = PR_Open(fname,
                                    PR_CREATE_FILE | PR_WRONLY | PR_TRUNCATE,
                                    0xFFFFFFFF);
        if (logfd)
        {
            PR_Write(logfd, output->data, len);
            PR_Close(logfd);
        }
    }
#endif
    return mystatus;
}

CRLInstance :: CRLInstance(const char* inurl, PRInt32 refresh, PRInt32 mage)
{
    memcpy(&mdObject, &revocator_prototype_mdObject,
           sizeof(revocator_prototype_mdObject));
    mdObject.etc = (void*) this;
    url = Rev_Strdup(inurl);
    subject = NULL;
    PR_ASSERT(url);
    period = refresh*oneminute; // PRTime in usecs
    maxage = mage*oneminute;
    derCRLData = NULL;
    crackedCRLData = NULL;
    lastfetchtime = lastupdatetime = nextupdatetime = 0;
    nextupdateok = PR_TRUE;
    syncLock = PR_NewLock();
    PR_ASSERT(syncLock);
    if (!syncLock)
    {
        current_status.setDetailedError(REV_ERROR_OUT_OF_MEMORY,
            "Out of memory. Unable to allocate lock object");
    }
}

void CRLInstance :: FreeDERCRL()
{
    if (derCRLData)
    {
        SECITEM_FreeItem(derCRLData, PR_TRUE);
        derCRLData = NULL;
    }
}

void CRLInstance :: FreeCrackedCRL()
{
    if (crackedCRLData)
    {
        SEC_DestroyCrl(crackedCRLData);
    }
    crackedCRLData = NULL;
}

CRLInstance :: ~CRLInstance()
{
    if (syncLock)
    {
        PR_DestroyLock(syncLock);
    }
    if (url)
    {
        Rev_Free(url);
    }
    if (subject)
    {
        Rev_Free(subject);
    }
    FreeCrackedCRL();
    FreeDERCRL();
}

const char* CRLInstance :: getURL() const
{
    return url;
}

const char* CRLInstance :: getSubject() const
{
    return subject;
}

void CRLInstance :: reportError(const RevStatus& mystatus) const
{
    NotifyFailure(getURL(), getSubject(), &mystatus);
}

RevStatus CRLInstance :: ProcessCRL(const SECItem& derCRL,
                                 CERTSignedCrl*& decodedCrl, PRTime now) const
{
    RevStatus mystatus;
    CERTCertDBHandle* cdb = CERT_GetDefaultCertDB();
    // inspired from mozilla/security/nss/lib/certhigh/certhigh.c
    CERTCertificate* caCert = NULL;
    SECStatus rv = SECSuccess;

    // first decode the DER CRL into a signed CRL
    decodedCrl = CERT_DecodeDERCrlWithFlags(NULL, (SECItem*)&derCRL, SEC_CRL_TYPE,
                                            CRL_DECODE_SKIP_ENTRIES | CRL_DECODE_DONT_COPY_DER);
    if (NULL == decodedCrl)
    {
        // only promote error when the error code is too generic
        mystatus.setDetailedError(REV_ERROR_BAD_DER_CRL,
                                  "Unable to decode DER CRL");
        return mystatus;
    }

    // for an update, compare DER subject of this new CRL against old one,
    // possible RA impersonation attack
    if (crackedCRLData &&
        SECITEM_CompareItem(&crackedCRLData->crl.derName,
                            &decodedCrl->crl.derName)!=0 )
    {
        mystatus.setDetailedError(REV_ERROR_CRL_SUBJECT_CHANGED,
            "Subject of this CRL changed. Possible compromission of the "
                                  "Revocation Authority or attack");
    }

    if (cdb)
    {
        if (!mystatus.hasFailed())
        {
            // check if we have the CA cert that this CRL applies to
            caCert = CERT_FindCertByName (cdb, &decodedCrl->crl.derName);
            if (NULL == caCert)
            {
                mystatus.setDetailedError(REV_ERROR_UNKNOWN_ISSUER,
                    "Unknown issuer for this CRL");
            }
        }
    
        if (!mystatus.hasFailed())
        {
            // If caCert is a v3 certificate, make sure that it can be used
            // for crl signing purpose
            rv = CERT_CheckCertUsage (caCert, KU_CRL_SIGN);
            if (rv != SECSuccess)
            {
                // only promote error when the error code is too generic
                mystatus.setDetailedError(REV_ERROR_BAD_ISSUER_USAGE,
                          "Incorrect usage for the CRL's issuer certificate");
            }
        }

        if (!mystatus.hasFailed())
        {
            // check that this certificate is a CA
            // we can't check for trust since the CRL could be for a chained
            // CA trusted by an upper level cert
            CERTCertTrust trust;
            SECStatus rv = CERT_GetCertTrust(caCert, &trust);
            PRInt32 flags = 0;

            if (SECSuccess != rv)
            {
                mystatus.setDetailedError(REV_ERROR_BAD_ISSUER_TRUST,
                          "No trust bits on issuer certificate");
            };

            if (!mystatus.hasFailed())
            {
                flags = trust.sslFlags;
                PRBool cert_is_ca = (0 != (flags & CERTDB_VALID_CA));

                if ( !cert_is_ca)
                {
                    // the issuer certificate is not for a CA . This is bad and
                    // revocator will reject it
                    mystatus.setDetailedError(REV_ERROR_BAD_ISSUER_TRUST,
                          "The issuer certificate of this CRL is not a Certificate Authority");
                }
            }
        }
    
        if (!mystatus.hasFailed())
        {
            // now verify the CRL's signature
            rv = CERT_VerifySignedData(&decodedCrl->signatureWrap,
                                       caCert, now, NULL);
            if (rv != SECSuccess)
            {
                mystatus.setDetailedError(REV_ERROR_BAD_CRL_SIG,
                                          "Unable to verify CRL signature");
            }
        }
    }
    else
    {
        // we don't have a trust domain and are therefore running inside
        // of an unmodified NSS app. We cannot do CRL signature
        // verification, so we will just skip the check
        // This isn't secure and is for testing only
    }

    // now free everything we don't need
    if (caCert)
    {
        CERT_DestroyCertificate(caCert);
    }

    if (!mystatus.hasFailed())
    {
        // everything good
        return mystatus;
    }
    else
    {
        // free the decoded CRL if we have one
        if (decodedCrl)
        {
            SEC_DestroyCrl(decodedCrl);
        }
        decodedCrl = NULL;
        // caller must check status
        return mystatus;
    }
}

RevStatus CRLInstance :: GetCRL(SECItem*& derCRL, CERTSignedCrl*& decodedCRL,
                                PRTime now) const
{
    RevStatus mystatus;

    derCRL = NULL;
    decodedCRL = NULL;

    // perform the CRL download here
    if ( (mystatus = DownloadCRL(url, globaltimeout, derCRL)).hasFailed())
    {
        return mystatus;
    }
    PR_ASSERT(derCRL);

    if (derCRL->len == 0) { /* no data retuned from server, this is ok */
        return mystatus;
    }

    // now check the CRL    
    if ((mystatus = ProcessCRL(*derCRL, decodedCRL, now)).hasFailed())
    {
        SECITEM_FreeItem(derCRL, PR_TRUE);
        derCRL = NULL;
        return mystatus;
    }
    PR_ASSERT(decodedCRL);

    return mystatus;
}

void CRLInstance :: notify(PRTime now) const
{
    NotifyDownload(getURL(), getSubject(), now, lastupdatetime,
                   nextupdatetime, maxage);
}

RevStatus CRLInstance :: fillCRL()
{
    RevStatus mystatus;
    PR_ASSERT(crackedCRLData);
    if (!crackedCRLData)
    {
        mystatus.setDetailedError(REV_ERROR_BAD_DER_CRL,
                                  "Unable to decode DER CRL");
    }

    // CRL subject
    if (!subject && crackedCRLData->crl.derName.data)
    {
        // only decode subject for the first download
        subject = CERT_DerNameToAscii(&crackedCRLData->crl.derName);
    }

    // lastupdate / nextupdate times
    lastupdatetime = nextupdatetime = 0;
    SECStatus rv = SECSuccess;
    if (crackedCRLData->crl.lastUpdate.data)
    {
        rv = DER_UTCTimeToTime(&lastupdatetime,
                               &crackedCRLData->crl.lastUpdate);
    }
    if ( (SECSuccess == rv) && crackedCRLData->crl.nextUpdate.data)
    {
        rv = DER_UTCTimeToTime(&nextupdatetime,
                               &crackedCRLData->crl.nextUpdate);
    }
    if (SECSuccess != rv)
    {
        // time conversion error
        mystatus.setDetailedError(REV_ERROR_INVALID_TIME,
                                  "Error in CRL time fields");
    }

    return mystatus;
}

void CRLInstance :: acquire()
{
    PR_ASSERT(syncLock);
    PR_Lock(syncLock);
}

void CRLInstance :: release()
{
    PR_ASSERT(syncLock);
    PR_Unlock(syncLock);
}

RevStatus CRLInstance :: update(const PRTime& now)
{
    RevStatus mystatus;
    SECItem* derCrl = NULL;
    CERTSignedCrl* decodedCrl = NULL;
    PRTime oldnextupdatetime = nextupdatetime;

    if ((mystatus = GetCRL(derCrl, decodedCrl, now)).hasFailed())
    {
        reportError(mystatus);
    }
    if (derCrl && derCrl->len == 0) { /* This is ok, see DownloadCRL */
        lastfetchtime = now;
        SECITEM_FreeItem(derCrl, PR_TRUE);
        derCrl = NULL;
        return mystatus;
    }

    if (!mystatus.hasFailed())
    {
        PR_ASSERT(derCrl);
        PR_ASSERT(decodedCrl);
        if (derCrl && decodedCrl)
        {
            PRBool newCRL = PR_FALSE;
            // replace the old CRL with the new one
    
            // we need to lock here in order to be safe from any PKCS#11 call
            // that would be looking at this CRL in the middle of its update
            acquire();
            // first, we need to check if this CRL is new or if it identical to the old one
            if ( (NULL == derCRLData) || (SECITEM_CompareItem(derCrl, derCRLData)!=0) )
            {
                // new CRL
                newCRL = PR_TRUE;
                // free the old CRL
                FreeCrackedCRL();
                FreeDERCRL();
                // assign the new CRL
                derCRLData = derCrl;
                crackedCRLData = decodedCrl;
                // update internal fields with new CRL data
                mystatus = fillCRL();
            }
            else
            {
                // identical CRL, simply free it
                SECITEM_FreeItem(derCrl, PR_TRUE);
                derCrl = NULL;
            }
            release();
            if (PR_TRUE == newCRL)
            {
                /* invalidate CRL cache */
                CERT_CRLCacheRefreshIssuer(NULL, (SECItem*)getDERSubject());
            }
        }
    }

    if (!mystatus.hasFailed())
    {
        // successful download
        notify(PR_Now());
        lastfetchtime = now; // use the time before the download
                             // so we don't get out of sync
        if (oldnextupdatetime != nextupdatetime)
        {
            // we got a new CRL with a different nextupdatetime, so it's OK
            // to try to fetch a new one when nextupdatetime becomes due
            // this unprotected access is safe as it only gets looked at or
            // updated from the download thread
            nextupdateok = PR_TRUE;
        }
    }
    else
    {
        // our download failed . The application was notified and will take
        // appropriate action
        // we need to prevent ourselves from going into an infinite download
        // loop. Mark the last fetch time as the time of this download
        // failure to accomplish this
        lastfetchtime = now;
    }
    return mystatus;
}

const PRTime CRLInstance :: remaining(const PRTime now)
{
    // first check if it's been more than a minute since our last update,
    // since we never want to update more frequently than that
    if (now - lastfetchtime < oneminute)
    {
        return oneminute - (now - lastfetchtime);
    }

    // check if we are past nextupdatetime
    if ( (nextupdatetime) && (nextupdateok) && (now >= nextupdatetime) )
    {
        // it's nextupdatetime, we are due for an update now
        nextupdateok = PR_FALSE; // only try once at nextupdatetime
        // if it fails, we will revert to the configured time period
        return 0;
    }

    // check configured period
    PRTime elapsed = now - lastfetchtime;
    if (elapsed>=period)
    {
        return 0; // up for refresh now
    }
    return period-elapsed; // remaining time
}

PRBool CRLManager :: freeAllCRLs()
{
    PR_ASSERT( (crls && numCrls) || (!crls && !numCrls));

    if (!numCrls || !crls)
    {
        return PR_FALSE;
    }

    PRInt32 counter;
    for (counter=0;counter<numCrls;counter++)
    {
        CRLInstance* crlptr = crls[counter];
        if (crlptr)
        {
            delete(crlptr);
        }
    }
    PR_Free(crls);
    numCrls = 0;
    crls = NULL;
    return PR_TRUE;
}

PRBool CRLManager :: addCRL(CRLInstance* newcrl)
{
    if (!numCrls)
    {
        // first CRL, allocate memory
        crls = (CRLInstance**)PR_Malloc((numCrls+1)*sizeof(CRLInstance*));
        if (!crls)
        {
            return PR_FALSE;
        }
    }
    else
    {
        // additional CRL, re-allocate memory
        CRLInstance** savcrls = crls;
        crls = (CRLInstance**)PR_Realloc(savcrls,
                                         (numCrls+1)*sizeof(CRLInstance*));
        if (!crls)
        {
            // don't leak all previous CRLs if we couldn't
            // allocate enough space for the new pointer
            crls = savcrls;
            freeAllCRLs();
            return PR_FALSE;
        }
    }
    crls[numCrls++] = newcrl;
    return PR_TRUE;
};

RevStatus CRLManager :: getStatus() const
{
    return current_status;
}

CRLManager :: CRLManager(RevocationInitString initstr) :
maxSleeptime(PR_SecondsToInterval(5))
{
    // initialize members
    crls = NULL;
    numCrls = 0;
    stopped = PR_FALSE;
    tid = NULL;

    // parse the initialization string and initialize CRLInstances
    char** crlstrings=NULL;
    PRInt32 configuredcrls = 0;
    // the last 3 values are special. They are:
    // -2: semaphore id used for locking
    // -1: pipe fd to read from
    //  0: pipe fd to read from
    PRBool status = Rev_ParseString(initstr, ' ', &configuredcrls,
                                    &crlstrings);
    configuredcrls-=3;
    if (PR_FALSE == status || (!configuredcrls) )
    {
        current_status.setDetailedError(
            REV_ERROR_BAD_CONFIG_STRING,
            "Unable to parse any CRL out of configuration string : %s",
            initstr);
        return;
    }
    semid = strtol(crlstrings[configuredcrls], NULL, 10);
    infd = strtol(crlstrings[configuredcrls+1], NULL, 10);
    outfd = strtol(crlstrings[configuredcrls+2], NULL, 10);

    // you've got CRLs
    PRInt32 counter;
    PRBool fatalerror = PR_FALSE;
    for (counter=0;counter<configuredcrls && !fatalerror;counter++)
    {
        char* crl = crlstrings[counter];
        PRInt32 attrcount=0;
        char** crlattrs=NULL;
        status = Rev_ParseString(crl, ';', &attrcount, &crlattrs);
        if (PR_FALSE == status)
        {
            // error, crl contains no attributes
            // this should never occur because the CRL string was parsed, so it
            // should have at least one attribute
            PR_ASSERT(0);
            current_status.setDetailedError(
                REV_ERROR_BAD_CRL_STRING,
                "Unable to parse individual CRL string : %s out of "
                "configuration string : %s",
                crl, initstr);
            fatalerror = PR_TRUE;
            break;
        }
        // we have got a CRL with some attributes
        // there should be three :
        // url, update period, and maximum age

        if (attrcount!=3)
        {
            current_status.setDetailedError(
                REV_ERROR_BAD_CONFIG_STRING,
                "Unable to parse individual CRL string : %s . Complete "
                "configuration string : %s",
                crl, initstr);
            fatalerror = PR_TRUE; // stop processing
        }

        // create a CRLInstance from the attributes
        if (!fatalerror)
        {
            const char* url = crlattrs[0];
            const char* refresh = crlattrs[1];
            const char* mage = crlattrs[2];
            CRLInstance* newcrl = new CRLInstance(url, atoi(refresh),
                                                  atoi(mage));
            if (!newcrl)
            {
                fatalerror = PR_TRUE;
                current_status.setDetailedError(REV_ERROR_OUT_OF_MEMORY,
                                                OutOfMemory);
            }
            else
            {
                PRBool added = addCRL(newcrl);
                if (!added)
                {
                    delete(newcrl);
                    fatalerror = PR_TRUE;
                    current_status.setDetailedError(REV_ERROR_OUT_OF_MEMORY,
                                                    OutOfMemory);
                }
            }
        }
        Rev_FreeParsedStrings(attrcount, crlattrs);
    }

    Rev_FreeParsedStrings(configuredcrls+3, crlstrings);
    if (fatalerror)
    {
        freeAllCRLs();
    }
}

RevStatus CRLManager :: DownloadAllCRLs()
{
    RevStatus mystatus;

    // download all CRLs at once for the first time
    PRInt32 counter;
    for (counter=0;counter<numCrls;counter++)
    {
        CRLInstance* acrl = crls[counter];
        mystatus = acrl->update(PR_Now());
        if (mystatus.hasFailed())
        {
            return mystatus;
        }
    }
    return mystatus;
}

void CRLManager :: MainLoop()
{
    // If we are in an unmodified NSS application which calls NSS_Shutdown(),
    // most likely an NSS command-line tool, and it is short-lived, then it
    // can crash in this thread if an update occurs during the shutdown
    // The above is for testing purposes only and not production apps
    // Real application should be modified to load this module explictly
    // after NSS_Initialize, and unload it before NSS_Shutdown,
    // using SECMOD_LoadUserModule and SECMOD_UnloadUserModule

    // this is the loop that keeps downloading new CRLs as needed,
    // based on each CRL's update period
    while (!stopped)
    {
        PRTime nextcrldelay=maxSleeptime;

        PRTime now = PR_Now();

        PRInt32 counter;
        for (counter=0;counter<numCrls;counter++)
        {
            CRLInstance* crlptr = crls[counter];
            PR_ASSERT(crlptr);
            PRTime remaining = crlptr->remaining(now);
            if (!remaining)
            {
                // this CRL is due for a refresh, do it now
                RevStatus status = crlptr->update(now);
                // update current time, since the update
                // involves a download and isn't instant
                now = PR_Now(); 
            }
            else
            {
                // this CRL is not yet due, but it may be less time to update
                // than our regular sleep time, so decrease sleep time
                // accordingly
                PRIntervalTime remint = PR_MicrosecondsToInterval((PRUint32) remaining);
                if (remint<nextcrldelay)
                {
                    nextcrldelay = remint;
                }
            }
        }
        PR_Sleep((PRUint32)nextcrldelay);
    }
}

extern "C" void CRLManagerStub(void* arg)
{
    CRLManager* crlm = (CRLManager*) arg;
    crlm->MainLoop();
}

RevStatus CRLManager :: StartEngine()
{
    RevStatus mystatus;
    // starts the background CRL manager thread
    // it needs to be a system thread
    // otherwise unmodified NSS applications will
    // deadlock in PR_Cleanup
    tid = PR_CreateThread(PR_SYSTEM_THREAD,
                                 CRLManagerStub,
                                 (void*) this,
                                 PR_PRIORITY_NORMAL,
                                 PR_GLOBAL_THREAD,
                                 PR_JOINABLE_THREAD,
                                 0);

    if (!tid)
    {
        mystatus.setDetailedError(REV_ERROR_START_FAILURE,
         "Unable to start revocation subsystem background download thread");
        NotifyFailure(NULL, NULL, &mystatus);
    }
    return mystatus;
};

PRInt32 CRLManager :: getNumCrls() const
{
    return numCrls;
}

void CRLManager :: stop()
{
    if (!tid)
    {
        return;
    }
    PR_AtomicSet((int*)&stopped, PR_TRUE);
    PR_JoinThread(tid);
    tid = NULL;
}

CRLInstance* CRLManager :: getCrl(const PRInt32 index)
{
    if (index<numCrls)
    {
        return crls[index];
    }
    else
    {
        return NULL;
    }
}

const SECItem* CRLInstance :: getDERSubject() const
{
    PR_ASSERT(crackedCRLData);
    if (crackedCRLData)
    {
        return &crackedCRLData->crl.derName;
    }
    else
    {
        return NULL;
    }
}

const SECItem* CRLInstance :: getDERCRL() const
{
    PR_ASSERT(derCRLData);
    if (derCRLData)
    {
        return derCRLData;
    }
    else
    {
        return NULL;
    }
}

NSSCKMDObject* CRLInstance :: getMdObject()
{
    return &mdObject;
}

