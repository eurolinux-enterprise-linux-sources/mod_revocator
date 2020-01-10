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
/* Copyright 2002-2004 The Apache Software Foundation
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

/*
 * mod_rev.h: Do automatic CRL retrieval and import.
 *
 * Rob Crittenden
 *
 */

/* 
 * Provide reasonable defines for some types
 */
#ifndef BOOL
#define BOOL unsigned int
#endif

#undef __REVOCATION_IMPLEMENTATION__

#include "revocation.h"
#include "secmod.h"

/* Our global configuration. There are no per-dir options */
typedef struct {
    int nInitCount;
    BOOL crlengine;
    BOOL crlagecheck;
    BOOL crlcritical;
    const char *crlfile;
    const char *crlhelper;
    const char *database;
    const char *dbprefix;
    const char *user;
    apr_proc_t proc;
    apr_procattr_t *procattr;
    int semid;
} rev_config;

#define REV_MOD_CONFIG_KEY "rev_module"

#define DLL_PREFIX "lib"
#if defined(HPUX11)
#define DLL_SUFFIX ".sl"
#else
#define DLL_SUFFIX ".so"
#endif
