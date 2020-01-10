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

#ifndef __CRLMANAGER__
#define __CRLMANAGER__

#include "nspr.h"
#include "revocation.h"
#include "certt.h"
#include "pkcs11layer.h"

class CRLInstance
{
public:
    CRLInstance(const char* url, PRInt32 refresh, PRInt32 mage);
    ~CRLInstance();

    RevStatus update(const PRTime& now);
    const PRTime remaining(const PRTime now);
    const char* getURL() const;
    const char* getSubject() const;
    const SECItem* getDERSubject() const;
    const SECItem* getDERCRL() const;

    void acquire();
    void release();
    NSSCKMDObject* getMdObject();

private:
    // configuration parameters
    char* url;
    char* subject;
    PRTime period;
    PRTime maxage;

    // DER CRL data
    SECItem* derCRLData;
    // cracked data from the CRL
    CERTSignedCrl* crackedCRLData;
    PRTime lastfetchtime;
    PRTime lastupdatetime;
    PRTime nextupdatetime;
    PRBool nextupdateok;

    // internal functions
    void reportError(const RevStatus&) const;
    void notify(PRTime now) const;
    RevStatus DownloadCRL(const char* url, const PRIntervalTime timeout,
                       SECItem*& output) const;
    RevStatus ProcessCRL(const SECItem& derCRL,
                         CERTSignedCrl*& decodedCrl, PRTime now) const;

    RevStatus GetCRL(SECItem*& derCRL, CERTSignedCrl*& decodedCRL,
                     PRTime now) const;
    void FreeDERCRL();
    void FreeCrackedCRL();
    RevStatus fillCRL();

    RevStatus current_status;
    PRLock* syncLock;

    // needed for CKFW
    NSSCKMDObject mdObject;
};

class CRLManager
{
public:
    CRLManager(RevocationInitString initstr);
    // the above constructor checks the revocation engine configuration

    RevStatus DownloadAllCRLs(); // as its name implies
    RevStatus StartEngine(); // starts the background CRL manager thread

    void MainLoop();
    const PRTime maxSleeptime;
    RevStatus getStatus() const;
    PRInt32 getNumCrls() const;
    void stop();
    CRLInstance* getCrl(const PRInt32 index);
    int semid;
    int infd;
    int outfd;

private:
    PRBool addCRL(CRLInstance* newcrl);
    PRBool freeAllCRLs();
    RevStatus current_status;
    PRInt32 numCrls;
    CRLInstance** crls;
    volatile PRBool stopped;
    PRThread* tid;
};

PR_EXTERN(CRLManager* crlm);

#endif

