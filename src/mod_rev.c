/** BEGIN COPYRIGHT BLOCK
 * Copyright (c) 2006-2010  Red Hat, Inc. All rights reserved.
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
 * mod_rev.c: Do automatic CRL retrieval and import.
 * 
 * The basic idea is:
 * - On the Apache first-run (which normally just validates the config) fire
 *   off the CRLHelper. Apache child process communicate to it over a two-way
 *   pipe. This is used to do actual CRL retrieval.
 * - Access is controlled to this via a semaphore. The semaphore is actually
 *   deleted in the CRLHelper program, otherwise we'd have troubles keeping
 *   it around between Apache reloads and closing it properly.
 * - The CRLFile parameter is parsed and it and the two pipe file descriptors
 *   are passed to a PKCS#11 module that handles the NSS side of things.
 * - When the PKCS#11 module determines it needs a new CRL it locks the
 *   semaphore, sends the request over the pipe and receives the response.
 * - The semaphore is then unlocked so the next child process can make a
 *   request.
 * - The CRLHelper caches responses for 58 seconds. The Apache children
 *   will generally make update requests at the same time and this will
 *   let us avoid frequent remote retrievals and still allow for quick
 *   CRL expiration (and it makes testing easier).
 *
 * Rob Crittenden
 *
 */

#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include "ap_config.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_dso.h"
#include "mod_rev.h"

module AP_MODULE_DECLARE_DATA rev_module;

SECStatus ShutdownRevocation(void *data);

static pid_t parent_pid;

apr_status_t rev_module_kill(void *data)
{
    server_rec *s = (server_rec *)data;
    rev_config * sc = (rev_config *)ap_get_module_config(s->module_config, &rev_module);

    /* The semaphore is removed in the helper program. This is because that
     * program survives Apache reloads so the semaphore will as well.
     */
    ShutdownRevocation(sc->crlengine); /* FIXME, should do something with return value */
    return APR_SUCCESS;
}

/*
 * Create the global config
 */
static void * mod_rev_server_create(apr_pool_t *p, server_rec *s) {
    rev_config * sc;
    void * vsc;

    apr_pool_userdata_get(&vsc, REV_MOD_CONFIG_KEY, s->process->pool);
    if (vsc) {
        return vsc; /* reused for lifetime of the server */
    }

    sc = (rev_config *)apr_palloc(s->process->pool, sizeof(rev_config));

    sc->nInitCount = 0;
    sc->crlengine = FALSE;
    sc->crlagecheck = FALSE;
    sc->crlcritical = FALSE;
    sc->crlfile = NULL;
    sc->crlhelper = NULL;
    sc->database = NULL;
    sc->dbprefix = NULL;
    sc->user = NULL;

    /* So we can save data between server restarts */
    apr_pool_userdata_set(sc, REV_MOD_CONFIG_KEY,
                          apr_pool_cleanup_null,
                          s->process->pool);

    return sc;
}

PRBool revocatorInitialized = PR_FALSE;

RevocationGetMessage RevGetMessage = NULL;

RevocationHasFailed RevHasFailed = NULL;

RevocationGetError RevGetError = NULL;

PRInt32 RevErrorToString(char* buffer, const PRInt32 maxlen, PRInt32 reverror)
{
    return 0;

#if 0
    const char* errstring = NULL;
    switch (reverror)
    {
        // XXX in the future, for i18n purposes, we'll need to map all errors
        // from reverror.h to other strings here and get the string reference
        // into errstring . This will create a lot of headaches due to variable
        // arguments in the string. Basically revocator will have to pass us
        // a va_list and we'll have to print it ourselves. But our strings
        // will need to be in sync.
        default:
            return PR_snprintf(buffer, maxlen, "%d", reverror);
    }
    if (errstring && buffer && maxlen)
    {
        strncpy(buffer, errstring, maxlen);
        return strlen(buffer);
    }
    else
    {
        return 0;
    }
#endif
}

PRBool NESRevocationFailureNotification(void* critical,
                                        const char* inurl,
                                        const char* insubject,
                                        const RevStatus* theerror)
{
    const char* errMsg = NULL;
    char errorbuf[256] = "";
    PRInt32 reverror;
    if (theerror)
    {
        reverror = RevGetError(theerror);
        errMsg = RevGetMessage(theerror);
        if (!errMsg)
        {
            if (RevErrorToString(errorbuf, sizeof(errorbuf), reverror))
            {
                errMsg = errorbuf;
            }
        }
    }
    if (!errMsg)
    {
        errMsg = "";
    }

    if (errMsg && !inurl && !insubject)
    {
        /* this is a generic revocator failure, not a download failure */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
            "Revocation subsystem failure : %s", errMsg);
    }
    else
    {    
        /* a CRL download failed */
        const char* url = NULL;
        const char* subject = NULL;
        if (!inurl)
        {
            url = "no url";
        }
        else
        {
            url = inurl;
        }
        if (!insubject)
        {
            subject = "no subject";
        }
        else
        {
            subject = insubject;
        }
        /* log error */
        if (reverror == REV_ERROR_NOUPDATE_AVAILABLE) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                "%s : %s %s",
                errMsg, url, subject ? subject : "");
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                "Error updating CRL %s %s : %s",
                url, subject ? subject : "", errMsg);
        }
    
        /* we have to shut down the server now,
         * unless we are called during initialization
         */
        if (critical && revocatorInitialized)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                "Critical CRL update failure. Shutting down server. %d", parent_pid);
            kill(parent_pid, 15);
        }
    }
    return PR_TRUE;
}

void PRTime2String(PRTime intime, char* buffer, PRInt32 len)
{
    PRExplodedTime exploded;
    if (!buffer || !len)
    {
        return;
    }
    PR_ExplodeTime(intime, PR_LocalTimeParameters, &exploded);
    PR_FormatTime(buffer, len, "%c", &exploded);
}

PRBool NESRevocationDownloadNotification(void *agecheck, void* s,
                                         const char* inurl,
                                         const char* insubject,
                                         PRTime curtime,
                                         PRTime lastupdate,
                                         PRTime nextupdate,
                                         PRTime maxage)
{
    const char* url = NULL;
    const char* subject = NULL;
    int loglevel = 0;
    char lastupdatestr[256];
    char nextupdatestr[256];

    if (!inurl)
    {
        url = "";
    }
    else
    {
        url = inurl;
    }
    if (!insubject)
    {
        subject = "";
    }
    else
    {
        subject = insubject;
    }
    /* log successful download notification */
    if (revocatorInitialized)
    {
        loglevel = APLOG_DEBUG;
    }
    else
    {
        loglevel = APLOG_INFO;
    }
    strncpy(lastupdatestr, "no last update", sizeof(lastupdatestr));
    strncpy(nextupdatestr, "no next update", sizeof(nextupdatestr));    
    
    if (lastupdate)
    {
        PRTime2String(lastupdate, &lastupdatestr[0], sizeof(lastupdatestr));
    }
    if (nextupdate)
    {
        PRTime2String(nextupdate, &nextupdatestr[0], sizeof(nextupdatestr));
    }

    ap_log_error(APLOG_MARK, loglevel, 0, (server_rec *) s,
        "Successfully downloaded CRL at URL %s, subject = %s, lastupdate = %s, nextupdate = %s", 
        url, subject, lastupdatestr, nextupdatestr);
    if (agecheck && maxage)
    {
        /* check if the currenttime - nextupdate is greater than maxage
         * first, do we have a nextupdate ?
         */
        if (nextupdate)
        {
            PRTime now = PR_Now();
            if (nextupdate < now)
            {
                /* this CRL is not the latest. How old is it already
                 * past nextupdate ?
                 */
                PRTime age = now -  nextupdate;
                if (age>maxage)
                {
                    /* this CRL is outdated, log it */
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                        "CRL %s %s is outdated. Shutting down server. %d",
                         url, subject, parent_pid);

                    /* we have to shut down the web server */
                    kill(parent_pid, 15);
                }
            }

        }
    }
    return PR_TRUE;
}

const char* revocation_library = DLL_PREFIX "revocation" DLL_SUFFIX;

static SECMODModule* mod = NULL;
static apr_dso_handle_t *dlh = NULL;

#define CONFIGLEN 4096

static int
init_Module(apr_pool_t *p, apr_pool_t *plog,
            apr_pool_t *ptemp, server_rec *s)
{
    rev_config * sc = (rev_config *)ap_get_module_config(s->module_config, &rev_module);
    struct semid_ds status;
    uid_t user_id;

    user_id = ap_uname2id(sc->user);

    /* We need the pid of the Apache server so we can kill it if things
     * go wrong.
     */
    parent_pid = getpid();
        
    sc->nInitCount++;

    /* The first pass through this function will create the semaphore that
     * will be used to lock the pipe. The user is still root at that point
     * so for any later calls the semaphore ops will fail with permission
     * errors. So switch the user to the Apache user.
     */
    if (sc->semid) {
        semctl(sc->semid, 0, IPC_STAT, &status);
        status.sem_perm.uid = user_id;
        semctl(sc->semid,0,IPC_SET,&status);
    }

    if (sc->nInitCount == 1) {
        const char * child_argv[5];
        apr_status_t rv;
        struct sembuf sb;
        char sembuf[32];

        if (sc->crlhelper == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "CRLHelper is not set. It is required.");
            nss_die();
        }

        sc->semid = semget(IPC_PRIVATE, 1, IPC_CREAT | IPC_EXCL | 0600);
        if (sc->semid == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "Unable to obtain semaphore.");
            nss_die();
        }

        /* Initialize the semaphore */
        sb.sem_num = 0;
        sb.sem_op = 1;
        sb.sem_flg = 0;
        if ((semop(sc->semid, &sb, 1)) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "Unable to initialize semaphore.");
            nss_die();
        }

        PR_snprintf(sembuf, 32, "%d", sc->semid);
        child_argv[0] = sc->crlhelper;
        child_argv[1] = sembuf;
        child_argv[2] = sc->database;
        child_argv[3] = sc->dbprefix;
        child_argv[4] = NULL;

        rv = apr_procattr_create(&sc->procattr, s->process->pool);

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "apr_procattr_create() failed APR err: %d.", rv);
            nss_die();
        }

        apr_procattr_io_set(sc->procattr, APR_PARENT_BLOCK, APR_PARENT_BLOCK,
                             APR_FULL_NONBLOCK);
        apr_procattr_error_check_set(sc->procattr, 1);

        /* the process inherits our environment, which should allow the
         * dynamic loader to find NSPR and NSS.
         */
        apr_procattr_cmdtype_set(sc->procattr, APR_PROGRAM_ENV);

        /* We've now spawned our helper process, the actual communication
         * with it occurs in the crlmanager.
         */
        rv = apr_proc_create(&sc->proc, child_argv[0], child_argv, NULL, sc->procattr, s->process->pool);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "apr_proc_create failed to launch %s APR err: %d.", child_argv[0], rv);
            nss_die();
        }
        /* Set a 30-second read/write timeout */
        apr_file_pipe_timeout_set(sc->proc.in, apr_time_from_sec(30));
        apr_file_pipe_timeout_set(sc->proc.out, apr_time_from_sec(30));
    }

    apr_pool_cleanup_register(p, s, rev_module_kill, apr_pool_cleanup_null);

    return APR_SUCCESS;
}

static int
InitRevocation(apr_pool_t *p, server_rec *base_server)
{
    apr_status_t status;
    char * configstring = NULL;
    rev_config * sc = (rev_config *)ap_get_module_config(base_server->module_config, &rev_module);
    void* agecheck = (void *)sc->crlagecheck;
    void* critical = (void *)sc->crlcritical;
    Rev_SetFailureCallbackEntryPoint setfcb = NULL;
    Rev_SetDownloadCallbackEntryPoint setncb = NULL;
    int infd, outfd;

    /* Do nothing until Apache is ready to run */
    if (sc->nInitCount < 2) return APR_SUCCESS;

    if (sc->crlengine == TRUE)
    {
        /* load library */
        status = apr_dso_load(&dlh, revocation_library, p);

        /* revocator can't load */
        if (status != APR_SUCCESS)
        {
            char errstr[256];

            apr_dso_error(dlh, errstr, 256);
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
                "Unable to load revocation subsystem library %s: %s.",
                revocation_library, errstr);
            return APR_EGENERAL;
        }

        /* get callback functions setters */
        apr_dso_sym((void *)&setfcb, dlh, "Rev_SetFailureCallback");
        apr_dso_sym((void *)&setncb, dlh, "Rev_SetDownloadCallback");
        apr_dso_sym((void *)&RevGetMessage, dlh, "Rev_getMessage");
        apr_dso_sym((void *)&RevGetError, dlh, "Rev_getError");
        apr_dso_sym((void *)&RevHasFailed, dlh, "Rev_hasFailed");

        if (!setfcb || !setncb || !RevGetMessage || !RevGetError || !RevHasFailed)
        {
            apr_dso_unload(dlh);
            return APR_EGENERAL;
        }

        /* set callback functions for logging */
        setfcb(&NESRevocationFailureNotification, critical);
        setncb(&NESRevocationDownloadNotification, agecheck, base_server);

        if (sc->crlfile == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
                         "Remote CRLs not specified. [Hint: set CRLFile]");
            return APR_EGENERAL;
        }

        if (sc->database == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
                         "NSS Certificate database not set [Hint: set NSSCertificateDatabase]");
            return APR_EGENERAL;
        }

        /* load PKCS#11 module */

        /* first build full configuration string */
        configstring = (char *)malloc(CONFIGLEN);

        apr_os_file_get(&outfd, sc->proc.in);
        apr_os_file_get(&infd, sc->proc.out);
        PR_snprintf(configstring, CONFIGLEN, "library=%s name=revocation parameters=\"%s %ld %d %d\"", revocation_library, sc->crlfile ? sc->crlfile : "", sc->semid, infd, outfd);

        mod = SECMOD_LoadUserModule(configstring, NULL, PR_FALSE);
        if (!mod || !mod->loaded)
        {
            if (mod)
            {
                SECMOD_DestroyModule(mod);
                mod = NULL;
            }
            free(configstring);
            apr_dso_unload(dlh);
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, base_server,
                 "Unable to load secmod module: %d", PR_GetError());
            return APR_EGENERAL;
        }
        free(configstring);
        revocatorInitialized = PR_TRUE;
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, base_server,
            "Revocation subsystem initialized %d", sc->nInitCount);
    }
    return APR_SUCCESS;
}

SECStatus
ShutdownRevocation(void *data)
{
    BOOL revsetting = (BOOL)data;
    SECStatus rv = SECFailure;

    if (TRUE != revsetting)
    {
        return SECSuccess;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, NULL,
        "Shutting down revocation");

    if (revocatorInitialized && mod)
    {
        rv = SECMOD_UnloadUserModule(mod);
        SECMOD_DestroyModule(mod);
        apr_dso_unload(dlh);
        mod = NULL;
        dlh = NULL;
        return rv;
    }
    else
    {
        /* can't shut down if not already started */
        return rv;
    }
}

static const char *set_user(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    rev_config *cf = ap_get_module_config(s->module_config, &rev_module);

    cf->user = arg;

    return NULL;
}

static const char *set_dbprefix(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    rev_config *cf = ap_get_module_config(s->module_config, &rev_module);

    cf->dbprefix = arg;

    return NULL;
}

static const char *set_database(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    rev_config *cf = ap_get_module_config(s->module_config, &rev_module);

    cf->database = arg;

    return NULL;
}

static const char *set_crlfile(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    rev_config *cf = (rev_config *)ap_get_module_config(s->module_config, &rev_module);

    cf->crlfile = arg;

    return NULL;
}

static const char *set_crlagecheck(cmd_parms *cmd, void *dummy, int arg)
{
    server_rec *s = cmd->server;
    rev_config *cf = ap_get_module_config(s->module_config, &rev_module);

    cf->crlagecheck = arg;

    return NULL;
}

static const char *set_crlcritical(cmd_parms *cmd, void *dummy, int arg)
{
    server_rec *s = cmd->server;
    rev_config *cf = ap_get_module_config(s->module_config, &rev_module);

    cf->crlcritical = arg;

    return NULL;
}

static const char *set_crlengine(cmd_parms *cmd, void *dummy, int arg)
{
    server_rec *s = cmd->server;
    rev_config *cf = ap_get_module_config(s->module_config, &rev_module);

    cf->crlengine = arg;

    return NULL;
}

static const char *set_crlhelper(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    rev_config *cf = (rev_config *)ap_get_module_config(s->module_config, &rev_module);

    if (access(arg, R_OK|X_OK) != -1) {
        cf->crlhelper = arg;
    } else {
        return ("CRLHelper does not exist or is not executable");
    }

    return NULL;
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const aszPre[] = { "mod_nss.c", NULL };
    ap_hook_post_config(init_Module, aszPre, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(InitRevocation, aszPre, NULL, APR_HOOK_MIDDLE);
}

static const command_rec mod_rev_cmds[] =
{
    AP_INIT_TAKE1("CRLFile", set_crlfile, NULL, RSRC_CONF,
                 "Specify the URL provided by your CA for downloading updated CRLs."),
    AP_INIT_TAKE1("CRLHelper", set_crlhelper, NULL, RSRC_CONF,
                  "Path to program that handles retrieving CRLs "
                  "(`/path/to/file`)"),
    AP_INIT_FLAG("CRLEngine", set_crlengine, NULL, RSRC_CONF,
                  "Enable or Disable CRL Revocation checking."),
    AP_INIT_FLAG("CRLAgeCheck", set_crlagecheck, NULL, RSRC_CONF,
                  "Shut down server if CRLs are too old."),
    AP_INIT_FLAG("CRLUpdateCritical", set_crlcritical, NULL, RSRC_CONF,
                  "Shut down server if CRL updates fail."),
    AP_INIT_TAKE1("NSSCertificateDatabase", set_database, NULL, RSRC_CONF,
                  "SSL Server Certificate database. Comes from nss.conf."),
    AP_INIT_TAKE1("NSSDBPrefix", set_dbprefix, NULL, RSRC_CONF,
                  "NSS database prefix. Comes from nss.conf."),
    AP_INIT_TAKE1("User", set_user, NULL, RSRC_CONF,
                  "Apache user. Comes from httpd.conf."),
    { NULL }
};

module AP_MODULE_DECLARE_DATA rev_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    mod_rev_server_create,      /* server config */
    NULL,                       /* merge server config */
    mod_rev_cmds,               /* command apr_table_t */
    register_hooks              /* register hooks */
};
