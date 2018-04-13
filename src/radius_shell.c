/*
 * Copyright (C) 2018 Cumulus Networks, Inc.
 * All rights reserved.
 * Author: Dave Olson <olson@cumulusnetworks.com>
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
 * This program exists to set the uid of privileged radius login users.
 * Due to the limitations of the RADIUS protocol, we can't determine
 * whether a user is privileged or not until they have authenticated,
 * and by then, some of the login mechanisms (openssh, e.g.) have already
 * determined the uid.
 *
 * This program looks at the accounting uid, and if set, and not the same
 * as the uid, and the auid is >= 1000, will try to reset the uid to the auid
 * as well as the fsuid.
 *
 * For this to work, the program must be installed as setcap cap_setuid.
 * As a minor additional safeguard, the program should be installed as
 * a member of the radius_users group, and permissions 750.
 *
 * Errors are written to stderr so the user logging in will see them,
 * rather than using syslog.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <libaudit.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/fsuid.h>
#include <sys/capability.h>

int main(int cnt, char **args)
{
	uid_t uid, auid;
	cap_value_t capability[] = { CAP_SETUID};
	cap_t capabilities;
	char *shell = NULL, *check = NULL, execshell[64];

	uid = getuid();
	auid = audit_getloginuid();

	if (uid < 1000 || auid < 1000 || auid == (uid_t)-1 || uid == auid) {
		/*  We try to be careful in what we will change  */
		goto execit;
	}

	if (setfsuid(auid) == -1)
		fprintf(stderr, "Failed to set fsuid to %u: %s\n",
			auid, strerror(errno));
	if (setresuid(auid, auid, auid))
		fprintf(stderr, "Failed to set uid to %u: %s\n",
			auid, strerror(errno));
	if (getuid() != auid)
		fprintf(stderr, "Failed to set uid to %u it's still %u\n",
			auid, getuid());

execit:
	/*  be paranoid, and clear our expected CAP_SETUID capability,
	 *  even though it should be cleared on exec.
	 */
	capabilities = cap_get_proc();
	if (capabilities) {
		if (!cap_set_flag(capabilities, CAP_EFFECTIVE, 1,
				   capability, CAP_CLEAR) &&
		    !cap_set_flag(capabilities, CAP_PERMITTED, 1,
					   capability, CAP_CLEAR)) {
		    if (cap_set_proc(capabilities))
			fprintf(stderr, "Failed to clear cap_setuid: %s\n",
				strerror(errno));
		    }
	}

#ifdef LATER
	/*
	 * Eventually handle this program being linked or symlinked
	 * and that the shell is one of the shells in /etc/shells
	 */
	shell = strrchr(args[0], '/');
	if (!shell)
		shell = args[0];

	if (*shell == '-') {
		check = shell + 1;
	}
	else
		check = shell;

	/* should really check this against /etc/shell */
	snprintf(execshell, sizeof execshell, "/bin/%s", check);
#else
	check = "bash";
	shell = "-bash";
	snprintf(execshell, sizeof execshell, "/bin/%s", check);
#endif

	execl(execshell, shell, NULL);
	fprintf(stderr, "Exec of shell %s failed: %s\n", execshell,
		strerror(errno));
	exit(1);
}
