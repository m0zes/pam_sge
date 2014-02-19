/*
 * Copyright (c) 2014, Adam Tygart
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *	 * Neither the name of Adam Tygart nor the
 *	   names of its contributors may be used to endorse or promote products
 *	   derived from this software without specific prior written permission.
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

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <sys/param.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <grp.h>

#include <security/pam_appl.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

struct JobData {
	char *user;
	int gid;
};
/*
 * read_file
 *
 * reads the file at 'file' for the struct JobData
 * returns 0 if the struct is empty;
 * returns 1 if the struct is populated;
 *
 */
int read_file(char* file, struct JobData **jd) {
	FILE *fp = fopen(file, "r");
	char line[10240];
	char key[5120];
	char val[5120];
	struct JobData *jdTemp = malloc(sizeof(struct JobData));
	int retval = 0;
	while (fscanf(fp, "%s", line) != EOF) {
		int i, found = -1;
		for (i = 0; i < strlen(line); i++) {
			if (found == -1) {
				if (line[i] == '=') {
					found = i;
					key[i] = '\0';
				} else {
					key[i] = line[i];
				}
			} else {
				if ((strcmp(key, "add_grp_id") == 0) || (strcmp(key, "job_owner") == 0)) {
					val[i-found-1] = line[i];
				} else {
					val[i-found-1] = '\0';
					break;
				}
			}
			if (i+1 == strlen(line)) {
				val[i-found] = '\0';
				if (strcmp(key, "job_owner") == 0) {
					syslog(LOG_DEBUG, "found job_owner (%s) in file (%s)", val, file);
					jdTemp->user = strdup(val);
					retval++;
				}
				if (strcmp(key, "add_grp_id") == 0) {
					syslog(LOG_DEBUG, "found add_grp_id (%s) in file (%s)", val, file);
					jdTemp->gid = atoi(val);
					retval++;
				}
			}
		}
	}
	fclose(fp);
	if (retval == 2) {
			*jd = jdTemp;
			return 1;
	} else {
			free(jdTemp);
			return 0;
	}
}
/*
 * recurse_find_file
 *
 * finds the config file in baseDir and puts it in the files array at current_len
 * recurses into subdirectories if config is not in the baseDir
 * returns the number of config files found.
 *
 */
int recurse_find_config(char* baseDir, char*** files, int current_len) {
	syslog(LOG_DEBUG, "Recursing into %s, found %i files already", baseDir, current_len);
	char *config = "config";
	DIR *dp = opendir(baseDir);
	struct dirent *ep;
	if (dp != NULL) {
		while ((ep = readdir(dp))) {
			if ((strcmp(ep->d_name, config) == 0)) {
				char *tmp = malloc(sizeof(char) * (strlen(baseDir) + strlen(config) + 1));
				int i;
				for (i = 0; i < strlen(baseDir); i++) {
					tmp[i] = baseDir[i];
				}
				for (i = 0; i < strlen(config); i++) {
					tmp[i+strlen(baseDir)] = config[i];
				}
				tmp[strlen(baseDir)+strlen(config)] = '\0';
				FILE *tmpfp = fopen(tmp, "r");
				if (tmpfp != NULL) {
					(*files)[current_len++] = strdup(tmp);
					syslog(LOG_DEBUG, "Found config file at %s", tmp);
					fclose(tmpfp);
				} else {
					syslog(LOG_WARNING, "Found config at %s, but cannot open the file", tmp);
				}
				free(tmp);
			} else if (ep->d_name[0] != '.') {
				// build full path to config file
				int i;
				char *tmp = malloc(sizeof(char) * (strlen(baseDir) + strlen(ep->d_name) + strlen(config) + 2));
				for (i = 0; i < strlen(baseDir); i++) {
					tmp[i] = baseDir[i];
				}
				for (i = 0; i < strlen(ep->d_name); i++) {
					tmp[i+strlen(baseDir)] = ep->d_name[i];
				}
				tmp[strlen(baseDir)+strlen(ep->d_name)] = '/';
				tmp[1+strlen(baseDir)+strlen(ep->d_name)] = '\0';
				DIR *tmpdp = opendir(tmp);
				if (tmpdp != NULL) {
					closedir(tmpdp);
					current_len = recurse_find_config(tmp, files, current_len);
				} else {
					syslog(LOG_DEBUG, "Found file at %s, not recursing", tmp);
				}
				free(tmp);
			}
		}
		closedir(dp);
	} else {
		syslog(LOG_ERR, "%s is not a directory.", baseDir);
	}
	return current_len;

}
/*
 * find_config_files
 *
 * sets up the baseDir for recurse_find_config
 * If baseDir is not null, it should be the path to the spool directory.
 * returns the number of config files found and the config filenames in the files array
 *
 */
int find_config_files(char* baseDir, char*** files) {
	if (baseDir == NULL) {
		baseDir = "/opt/sge/default/spool/";
	}
	syslog(LOG_DEBUG, "Finding config files in base: %s", baseDir);
	char *jobdir = "/active_jobs/";
	char *hname = malloc(sizeof(char) * 64);
	int hnamelen = 64;
	gethostname(hname, hnamelen);
	char *active_jobs = malloc(sizeof(char) * (strlen(baseDir) + strlen(hname) + strlen(jobdir) + 1));
	int i;
	// Build the active_jobs string (full path for where the active_jobs folder is)
	for (i = 0; i < strlen(baseDir); i++) {
		active_jobs[i] = baseDir[i];
	}
	for (i = 0; i < strlen(hname); i++) {
		active_jobs[i+strlen(baseDir)] = hname[i];
	}
	for (i = 0; i < strlen(jobdir); i++) {
		active_jobs[i+strlen(baseDir)+strlen(hname)] = jobdir[i];
	}
	active_jobs[strlen(baseDir)+strlen(hname)+strlen(jobdir)] = '\0';

	char **tmpFiles = malloc(sizeof(char*)*1000);
	int fileIndex = recurse_find_config(active_jobs, &tmpFiles, 0);
	syslog(LOG_INFO, "Found %i config files", fileIndex);
	free(active_jobs);
	free(hname);
	*files = tmpFiles;
	return fileIndex;
}
/*
 * check_sge_auth: the main auth function
 * Pass in the user you are looking for, and the starting directory, and it will
 * find all active jobs on the host by looking at their config files.
 * Returns 0 for non-existent users
 * Returns 1 for existing users.
 */
int check_sge_auth(const char* user, char* baseDir) {
	syslog(LOG_DEBUG, "Checking for USER=%s", user);
	char **configFiles = NULL;
	int num_config_files = find_config_files(baseDir, &configFiles);
	int i;
	struct JobData **jobs_data = malloc(sizeof(struct JobData*)*num_config_files);
	int user_found = 0;
	for (i=0; i < num_config_files; i++) {
		int out = read_file(configFiles[i], &jobs_data[i]);
		if ((out == 1) &&((strcmp(user, jobs_data[i]->user)) == 0)) {
			syslog(LOG_INFO, "Found matching user (%s) in file (%s)", user, configFiles[i]);
			user_found = 1;
		}
		free(configFiles[i]);
		free(jobs_data[i]->user);
		free(jobs_data[i]);
	}
	free(configFiles);
	free(jobs_data);
	return user_found;
}
/*
 * sge_set_groups
 * Pass in user and baseDir and it finds the configs/gids of the associated jobs.
 * It adds all of the gids to the shell meaning the process *will* get culled as soon as the first
 * job finishes.
 * This doesn't report the success of the the setgroups call except in LOG_DEBUG
 * Returns 0 for non-existent users
 * Returns 1 if the user exists
 */
int sge_set_groups(const char* user, char* baseDir) {
	syslog(LOG_DEBUG, "Checking for USER=%s added gids", user);
	char **configFiles = NULL;
	int num_config_files = find_config_files(baseDir, &configFiles);
	int i;
	struct JobData **jobs_data = malloc(sizeof(struct JobData*)*num_config_files);
	int user_found = 0;
	int curr_no_grps = getgroups(0, NULL);
	gid_t *all_gids = malloc(sizeof(gid_t) * (curr_no_grps + num_config_files));
	curr_no_grps = getgroups(curr_no_grps, all_gids);
	for (i=0; i < num_config_files; i++) {
		int out = read_file(configFiles[i], &jobs_data[i]);
		if ((out == 1) && ((strcmp(user, jobs_data[i]->user)) == 0)) {
			syslog(LOG_INFO, "Found matching user (%s) in file (%s)", user, configFiles[i]);
			syslog(LOG_DEBUG, "Adding GID (%i) for user (%s)", jobs_data[i]->gid, user);
			all_gids[curr_no_grps++] = jobs_data[i]->gid;
			user_found = 1;
		}
		free(configFiles[i]);
		free(jobs_data[i]->user);
		free(jobs_data[i]);
	}
	int status = setgroups(curr_no_grps, all_gids);
	syslog(LOG_DEBUG, "Setting Groups for user (%s)", user);
	if (status != 0) {
		syslog(LOG_WARNING, "Couldn't set the groups for user (%s), err: %i", user, status);
	}
	free(all_gids);
	free(configFiles);
	free(jobs_data);
	return user_found;
}
/*
 * pam_sm_authenticate.
 * This implementation reads the module arguments and Queries SGE files for access to the host.
 */
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

	pam_err = PAM_AUTH_ERR;
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
		if ((strcmp("SPOOL", key)) == 0) {
			baseDir = val;
		}
		if ((strcmp("LOGLEVEL", key)) == 0) {
			if ((strcmp("DEBUG", val)) == 0)
				setlogmask(LOG_UPTO(LOG_DEBUG));
			else if ((strcmp("INFO", val)) == 0)
				setlogmask(LOG_UPTO(LOG_INFO));
			else if ((strcmp("WARN", val)) == 0)
				setlogmask(LOG_UPTO(LOG_WARNING));
			else if ((strcmp("ERR", val)) == 0)
				setlogmask(LOG_UPTO(LOG_ERR));
			else
				setlogmask(LOG_UPTO(LOG_ERR));
		}
	}
	openlog("pam_sge_authenticate", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	if (check_sge_auth(user, baseDir))
		pam_err = PAM_SUCCESS;
	closelog();

	return pam_err;
}

/*
 * pam_sm_setcred: Module doesn't support, pretend it worked.
 */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	const char *user;
	char *baseDir = NULL;
	int pam_err;

	/* identify user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return (pam_err);

	pam_err = PAM_AUTH_ERR;
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
		if ((strcmp("SPOOL", key)) == 0) {
			baseDir = val;
		}
		if ((strcmp("LOGLEVEL", key)) == 0) {
			if ((strcmp("DEBUG", val)) == 0)
				setlogmask(LOG_UPTO(LOG_DEBUG));
			else if ((strcmp("INFO", val)) == 0)
				setlogmask(LOG_UPTO(LOG_INFO));
			else if ((strcmp("WARN", val)) == 0)
				setlogmask(LOG_UPTO(LOG_WARNING));
			else if ((strcmp("ERR", val)) == 0)
				setlogmask(LOG_UPTO(LOG_ERR));
			else
				setlogmask(LOG_UPTO(LOG_ERR));
		}
	}
	openlog("pam_sge_setcred", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	if (sge_set_groups(user, baseDir))
		pam_err = PAM_SUCCESS;
	closelog();

	return pam_err;
}

/*
 * pam_sm_acct_mgmt: Support account from pam by calling pam_sm_authenticate
 */
PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags,
	int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

/*
 * pam_sm_open_session: Support session from pam by calling pam_sm_authenticate
 */
PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags,
	int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

/*
 * pam_sm_close_session: Support session from pam by calling pam_sm_authenticate
 */
PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags,
	int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

/*
 * pam_sm_chauthtok: Support passwd from pam by calling pam_sm_authenticate
 */
PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *pamh, int flags,
	int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

/*
 * define the struct for a static pam module.
 */
#ifdef PAM_STATIC
struct pam_module _pam_sge_modstruct = {
	"pam_sge",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok,
};
#endif

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_sge");
#endif
