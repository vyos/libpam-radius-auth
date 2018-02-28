/* Copyright 2018 Cumulus Networks, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 */

/*
 * support routines for Cumulus Linux RADIUS client support.
 * They create the flat file mapping for the session, and create
 * the home directory if needed.
 * See the libnss-mapuser source for how the flat file database
 * is used.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <libaudit.h>
#include "pam_radius_auth.h"

static const char mapdir[] = "/run/mapuser";

static unsigned get_sessionid(void)
{
	int fd = -1, cnt = 0;
	unsigned id = 0U;
	static char buf[12];

	fd = open("/proc/self/sessionid", O_RDONLY);
	if (fd != -1) {
		cnt = read(fd, buf, sizeof(buf));
		close(fd);
	}
	if (fd != -1 && cnt > 0) {
		id = strtoul(buf, NULL, 0);
	}
	return id;
}

/*
 * Write the mapping file used by libnss-mapuser into mapdir/SESSIONID
 * This info is used by the mapuser and mapuid NSS plugins to return
 * correct information for users that are logged in using mapping (that
 * is, are not present in the password database(s)).
 * This allows very simple configuration of RADIUS clients, since it's
 * no longer necessary to add all user accounts to the local /etc/passwd
 * file (or use LDAP, etc.).
 */
void
__write_mapfile(pam_handle_t * pamh, const char *user, uid_t uid,
		int privileged, int debug)
{
	char tmstr[64], tmpstr[64];
	struct timeval tv = { 0, 0 };
	struct tm *tmv;
	int res = 0;
	unsigned session;
	uid_t auid;
	pid_t pid;
	FILE *f;

	(void)gettimeofday(&tv, NULL);
	tmv = localtime(&tv.tv_sec);
	*tmstr = '\0';
	if (tmv)
		res = strftime(tmpstr, sizeof tmpstr, "%FT%T", tmv);

	if (!res && !*tmstr)
		snprintf(tmpstr, sizeof tmpstr, "%llu",
			 (unsigned long long)tv.tv_sec);

	snprintf(tmstr, sizeof tmstr, "%s.%u", tmpstr, (unsigned)tv.tv_usec);

	auid = audit_getloginuid();
	if (auid == ~0U) {	/* normal case */
		audit_setloginuid(uid);
		auid = audit_getloginuid();
	}
	session = get_sessionid();
	pid = getpid();

	if (auid == 0 || auid == ~0U || session == ~0U) {
		/*  if these aren't valid, we can't use the mapfile, so
		 *  don't create it
		 */
		if (debug)
			pam_syslog(pamh, LOG_DEBUG, "Skipping mapfile user=%s"
				   " auid=%u session=%u", user, auid, session);
		return;

	}

	/*  won't hurt if it already exists, no more overhead than stat() first */
	mkdir(mapdir, 0755);
	snprintf(tmpstr, sizeof tmpstr, "%s/%u", mapdir, session);
	/*
	 * Only create if it doesn't exist.  It might exist if we are called from
	 * su or sudo after a login, for example
	 */
	f = fopen(tmpstr, "wx");
	if (!f) {
		if (errno != EEXIST)
			pam_syslog(pamh, LOG_WARNING,
				   "Can't create mapfile %s for user (%s): %m",
				   tmpstr, user);
		return;
	}
	res =
	    fprintf(f,
		    "%s\nuser=%s\npid=%u\nauid=%u\nsession=%u\nprivileged=%s\n",
		    tmstr, user, pid, auid, session, privileged ? "yes" : "no");
	if (fclose(f) == EOF || res <= 0)
		pam_syslog(pamh, LOG_WARNING, "Error writing mapfile %s for"
			   " user (%s): %m", tmpstr, user);
}

/*
 * Remove the mapping file used by libnss-mapuser into mapdir/SESSIONID
 * based on the session.  called from pam's sm_close entry point.
 * return 0 if not removed, 1 if removed.   This is so we can avoid
 * talking to the RADIUS server if the close entry point isn't for
 * one of our sessions.
 */
int __remove_mapfile(pam_handle_t * pamh, const char *user, int debug)
{
	unsigned session;
	uid_t auid;
	pid_t pid;
	int auidmatch = 0, sessmatch = 0, pidmatch = 0, usermatch = 0;
	char mapfile[64], linebuf[128];
	FILE *f;

	if (!user)
		return 0;	/* shouldn't ever happen */
	pid = getpid();
	session = get_sessionid();
	if (!session || session == (uid_t) - 1)
		return 0;
	snprintf(mapfile, sizeof mapfile, "%s/%u", mapdir, session);
	f = fopen(mapfile, "r");
	if (!f)
		return 0;
	auid = audit_getloginuid();
	while (fgets(linebuf, sizeof linebuf, f)) {
		unsigned long val;
		char *ok;
		if (!strncmp(linebuf, "session=", 8)) {
			val = strtoul(linebuf + 8, &ok, 0);
			if (val == session && ok != (linebuf + 8))
				sessmatch = 1;
		} else if (!strncmp(linebuf, "user=", 5)) {
			strtok(linebuf + 5, " \t\n\r\f");
			if (!strcmp(user, linebuf + 5))
				usermatch = 1;
		} else if (!strncmp(linebuf, "auid=", 5)) {
			val = strtoul(linebuf + 5, &ok, 0);
			if (val == auid && ok != (linebuf + 5))
				auidmatch = 1;
		} else if (!strncmp(linebuf, "pid=", 4)) {
			val = strtoul(linebuf + 4, &ok, 0);
			if (val == pid && ok != (linebuf + 4))
				pidmatch = 1;
		}
	}
	fclose(f);
	if (auidmatch && pidmatch && sessmatch && usermatch) {
		if (unlink(mapfile))
			pam_syslog(pamh, LOG_WARNING,
				   "Remove mapfile %s for user %s failed: %m",
				   mapfile, user);
	}
	else if (debug)
		pam_syslog(pamh, LOG_DEBUG, "mapfile %s user %s not removed,"
			   " doesn't match", mapfile, user);
	return 1;
}

/*
 * check to see if the home directory for the user exists
 * and create it using the mkhomedir_helper if it does not.
 * The code is based on the pam_mkhomedir plugin source
 * It must be called after the mapping file is written, or
 * getpwnam() won't be able to return the correct information
 * using the libnss-mapuser plugin (which is what we expect
 * for this RADIUS client).
 */
void
__chk_homedir(pam_handle_t * pamh, const char *user, const char *homedir,
	      int debug)
{
	int rc, retval, child, restore = 0;
	struct stat st;
	struct sigaction newsa, oldsa;
	const char *path = "/sbin/mkhomedir_helper";

	if (stat(homedir, &st) == 0)
		return;
	if (debug)
		pam_syslog(pamh, LOG_NOTICE,
			   "creating home directory %s for user %s", homedir,
			   user);

	/*
	 * Ensure that when child process exits that the program using PAM
	 * doesn't get a signal it isn't expecting, which might kill the
	 * program, or confuse it.
	 */
	memset(&newsa, '\0', sizeof(newsa));
	newsa.sa_handler = SIG_DFL;
	if (sigaction(SIGCHLD, &newsa, &oldsa) == 0)
		restore = 1;

	child = fork();
	if (child == -1) {
		pam_syslog(pamh, LOG_ERR, "fork to exec %s %s failed: %m",
			   path, user);
		return;
	}
	if (child == 0) {
		execl(path, path, user, NULL);
		pam_syslog(pamh, LOG_ERR, "exec %s %s failed: %m", path, user);
		exit(1);
	}

	while ((rc = waitpid(child, &retval, 0)) < 0 && errno == EINTR) ;
	if (rc < 0)
		pam_syslog(pamh, LOG_ERR,
			   "waitpid for exec of %s %s failed: %m", path, user);
	else if (!WIFEXITED(retval))
		pam_syslog(pamh, LOG_ERR, "%s %s abnormal exit: 0x%x", path,
			   user, retval);
	else {
		retval = WEXITSTATUS(retval);
		if (retval)
			pam_syslog(pamh, LOG_ERR, "%s %s abnormal exit: %d",
				   path, user, retval);
	}

	if (restore)
		sigaction(SIGCHLD, &oldsa, NULL);
}
