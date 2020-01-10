/* Copyright 2001-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <nss.h>
#include <nspr.h>
#include <secitem.h>
#include <prtypes.h>
#include <seccomon.h>
#include <pk11func.h>
#include <secmod.h>
#include "client.h"
#include "client_err.h"

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
    struct seminfo *__buf;
};

const PRTime oneminute = 50000000;

/*
 * Node - for maintaining link list of tokens with cached PINs
 */
typedef struct Node Node;

struct Node
{
  Node *next;
  char *url;
  void *data;
  int len;
  int errnum;
  PRTime fetchtime;
};

/*
 * Node implementation
 */

static void freeNode(Node *node)
{
    free(node->url);
    free(node->data);
    free(node);
}

static void freeList(Node *list)
{
    Node *n1;
    Node *n2;

    n1 = list;

    while (n1) {
        n2 = n1;
        n1 = n2->next;
        freeNode(n2);
    }
}

#ifdef DEBUG
static void printList(Node *list)
{
    Node *n1;
    int count = 0;

    n1 = list;

    fprintf(stderr, "Node list:\n");
    while (n1) {
        fprintf(stderr, "%lld: %s (%d)\n", n1->fetchtime, n1->url, n1->len);
        n1 = n1->next;
        count++;
    }
    fprintf(stderr, "%d Nodes\n", count);
}
#endif

/* global variables */
Node *urlcache = NULL;

int main(int argc, char ** argv)
{
    SECStatus rv;
    PRInt32 numfds;
    PRFileDesc *in;
    PRFileDesc *out;
    PRPollDesc pd;
    PRIntervalTime timeout = PR_INTERVAL_NO_TIMEOUT;
    int semid;
    union semun semarg;
    char buf[4096];
    char url[4096];
    PRTime lastfetchtime;
    PRTime now;
    PRInt32 nBytes;
    int fdlimit = sysconf(_SC_OPEN_MAX);
    int fd;
    void *data = NULL;
    PRInt32 len = 0;
    PRInt32 errnum = -1;

    /* Close all fds but stdin, stdout and stderr */
    fd = 3;
    while (fd < fdlimit)
        close(fd++);

    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: crlhelper <semid> <directory> <prefix>\n");
        exit(1);
    }

    semid = strtol(argv[1], NULL, 10);

    /* Initialize NSPR */
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 256);
 
    /* Initialize NSS and open the certificate database read-only. */
    rv = NSS_Initialize(argv[2], argc == 4 ? argv[3] : NULL, argc == 4 ? argv[3] : NULL, "secmod.db", NSS_INIT_READONLY);

    if (rv != SECSuccess) {
        fprintf(stderr, "Unable to initialize NSS database: %d\n", rv);
        exit(1);
    }

    in = PR_GetSpecialFD(PR_StandardInput);
    out = PR_GetSpecialFD(PR_StandardOutput);
    if (in == NULL || out == NULL) {
        fprintf(stderr, "PR_GetInheritedFD failed\n"); 
        exit(1);
    }

    pd.fd = in;
    pd.in_flags = PR_POLL_READ | PR_POLL_EXCEPT;
    while (1) {
        char outbuf[32];
        numfds = PR_Poll(&pd, 1, timeout);
        if (numfds == -1) { /* PR_Poll failed */
            break;
        }
        if (pd.out_flags & (PR_POLL_HUP | PR_POLL_ERR | PR_POLL_NVAL | PR_POLL_EXCEPT)) {
            break;
        }
        if (pd.out_flags & PR_POLL_READ) {
            Node *node;
            Node *prev;
            PRBool expired;

            memset(buf, 0, sizeof(buf));
            nBytes = PR_Read(in, buf, sizeof(buf));
            if (nBytes == 0) {
                break;
            }
            if (nBytes == -1) {
                syslog(LOG_ERR, "PR_Read failed: %d", PR_GetError());
                goto done;
            }
            lastfetchtime=0;
            if ((sscanf(buf, "%lld %s", &lastfetchtime, url)) != 2) {
                syslog(LOG_ERR, "Invalid request: %s", buf);
                goto done;
            }
            if (url[strlen(url)-1] == '\n') /* for interactive testing */
                url[strlen(url)-1] = '\0';
#ifdef DEBUG
            if (!(strcmp(url, "p"))) {
                printList(urlcache);
                continue;
            }
#endif

            /*
             * TODO: 
             *  - expire cache entries
             */
            data = NULL;
            errnum = -1;
            len = 0;
            prev = NULL;
            expired = PR_FALSE;
            for (node = urlcache; node != NULL; node = node->next) {
                if (!strcmp(node->url, url)) {
                    PRTime now = PR_Now();
                    /* 60 seconds is the minimum amount of time we
                     * wait before re-fetching a CRL (crlmanager.cpp). So
                     * we'll set the difference here at 50 seconds to be
                     * on the safe side. We don't really want cache choices
                     * made here but we want to limit the number of
                     * requests.
                     */
                    if (now - node->fetchtime < oneminute) {
                        data = node->data;
                        len = node->len;
                        errnum = node->errnum;
			goto done;
                    } else {
                        expired = PR_TRUE;
                        break;
                    }
                } else {
                    prev = node;
                }
            }
            if (NULL == data) {
                data = fetch_url(url, 30, lastfetchtime, &len, &errnum);
                if (expired)
                    if (errnum == CL_NOUPDATE_AVAILABLE) {
                        node->fetchtime = PR_Now();
                        data = node->data;
                        len = node->len;
                        node->errnum = errnum;
                        goto done;
                    } else {
                        if (prev) {
                            prev->next = node->next;
                        } else {
                            urlcache = node->next;
                        }
                        freeNode(node);
                }
                if (data) {
                    node = (Node *)malloc(sizeof(Node));
                    if (!node) {
                        syslog(LOG_ERR, "failed to alloc node");
                        goto done;
                    }
                    node->url = strdup(url);
                    node->data = (void *)malloc(len);
                    if (!node->data) {
                        syslog(LOG_ERR, "failed to alloc %d bytes", len);
                        goto done;
                    }
                    node->len = len;
                    memcpy(node->data, data, len);
                    free_url(data);
                    data = node->data;
                    node->fetchtime = PR_Now();
                    node->errnum = errnum;
                    if (urlcache)
                        node->next = urlcache;
                    else
                        node->next = NULL;
                    urlcache = node;
                }
            }

            /*
             * The output protocol is:
             *   errnum
             *   space
             *   len
             *   space
             *   bytes
             */
done:
            sprintf(outbuf, "%d %d ", errnum, len);
            if ((PR_Write(out, outbuf, strlen(outbuf))) == -1) {
                syslog(LOG_ERR, "PR_Write failed: %d", PR_GetError());
            }
            if ((PR_Write(out, data, len)) == -1) {
                syslog(LOG_ERR, "PR_Write failed: %d", PR_GetError());
            }
        } /* end POLL */
    } /* end while */
    freeList(urlcache);
    PR_Close(in);
    NSS_Shutdown();

    /* Remove the semaphore used for locking here. This is because this
     * program only goes away when Apache shuts down so we don't have to
     * worry about reloads.
     */
    semctl(semid, 0, IPC_RMID, semarg);
    return 0;
}
