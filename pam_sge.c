/*
 * Copyright (c) 2011, Adam Tygart
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Adam Tygart nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of the
 * GNU General Public License, in which case the provisions of the GNU
 * GPL are required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential conflict between the GNU GPL and the
 * restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL ADAM TYGART BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Compile
 *
 * gcc -fPIC -c pam_sge.c -Wall
 * ld -x --shared -o pam_sge.so pam_sge.o
 */

#include <security/pam_modules.h>
#include <sys/param.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

int read_file(const char *user, char *file) {
    FILE *fp = fopen(file, "r");
    //setlogmask(LOG_UPTO(LOG_WARNING));
    //openlog("pam_sge_read", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    if (fp == NULL) {
        return 0;
    }
    int retval = 0;
    char line[140];
    char key[140];
    char val[140];
    while (fscanf(fp, "%s", line) != EOF) {
        int i, found = - 1;
        for (i = 0; i < strlen(line); i++) {
            if (found == -1) {
                if (line[i] == '=') {
                        found = i;
                        key[i] = '\0';
                } else {
                        key[i] = line[i];
                }
            } else {
                if ((strcmp(key, "USER")))
                    val[i-found-1] = line[i];
                else {
                    val[i-found-1] = '\0';
                    break;
                }
            }
            if (i+1 == strlen(line))
                val[i-found] = '\0';
        }
	
        //syslog(LOG_WARNING, "read key (%s) and val (%s)", key, val);
        if ((strcmp(key, "USER")) && (strcmp(val, user))) {
            retval = 1;
            break;
	    }
    }
    fclose(fp);
    return retval;
}

int check_sge(const char *user, char *baseDir) {
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("pam_sge", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    if (baseDir == NULL)
            baseDir = "/active_jobs/";
    char *dir = "/opt/sge/default/spool/";
    char *env = "/environment";
    char *hname = malloc(sizeof(char) * 16);
    int hnamelen = 16;

    gethostname(hname, hnamelen);

    char *ajobs = malloc(sizeof(char) * (strlen(dir) + strlen(hname) + strlen(baseDir)));
    int i;
    for (i = 0; i < strlen(dir); i++)
        ajobs[i] = dir[i];

    for (i = 0; i < strlen(hname); i++)
        ajobs[i+strlen(dir)] = hname[i];

    for (i = 0; i < strlen(baseDir); i++)
        ajobs[i+strlen(dir)+strlen(hname)] = baseDir[i];

    DIR *dp = opendir(ajobs);
    struct dirent *ep;
    int retval = 0;
    
    if (dp != NULL) {
        while ((ep = readdir(dp))) {
            if (ep->d_type == 4) {
                char *tmp = malloc(sizeof(char) * (strlen(ajobs) + strlen(ep->d_name) + strlen(env)));
                for (i = 0; i < strlen(ajobs); i++)
                    tmp[i] = ajobs[i];
                for (i = 0; i < strlen(ep->d_name); i++)
                    tmp[i+strlen(ajobs)] = ep->d_name[i];
                for (i = 0; i < strlen(env); i++)
                    tmp[i+strlen(ajobs)+strlen(ep->d_name)] = env[i];
                syslog(LOG_INFO, "checking for USER (%s) in %s", user, tmp);
                if (read_file(user, tmp))
                    retval = 1;
                free(tmp);
                if (retval == 1)
                    break;
            }
        }
        closedir(dp);
    }
    free(ajobs);
    free(hname);
    return retval;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    const char *user;
    char *baseDir = NULL;
    int pam_err;

    /* identify user */
    if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
        return (pam_err);

    int i;
    for (i=0; i < argc; i++) {
        char key[140];
        char val[140];
        int found = -1;
        int j;
        for (j = 0; j < strlen(argv[i]); j++)
            if ((found == -1) && (argv[i][j] != '='))
                key[j] = argv[i][j];
            else if (argv[i][j] == '=')
                found = j;
            else
                val[j-found-1] = argv[i][j];
        if (strcmp("SPOOL", key)) {
                baseDir = val;
        }


    }

    /* Check against SGE */
    if (check_sge(user, baseDir))
        return PAM_SUCCESS;

    return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SUCCESS);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_sge");
#endif
