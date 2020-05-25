/*
 * pam_radius_auth
 *      Authenticate a user via a RADIUS session
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * The original pam_radius.c code is copyright (c) Cristian Gafton, 1996,
 *                                             <gafton@redhat.com>
 *
 * Some challenge-response code is copyright (c) CRYPTOCard Inc, 1998.
 *                                              All rights reserved.
 *
 * Copyright (C) 2017, 2018 Cumulus Networks, Inc.
 * All rights reserved.
 */

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include "pam_radius_auth.h"

#define DPRINT if (debug || cfg_debug) _pam_log

static int cfg_debug;
static int cleaned_up;

/* logging */
static void _pam_log(pam_handle_t * pamh, int err, CONST char *format, ...)
{
	va_list args;

	va_start(args, format);
	pam_vsyslog(pamh, err, format, args);
	va_end(args);

}

/*  base config, plus config file, but no pam cmdline */
static radius_conf_t savconf = {.min_priv_lvl = 15,	/* default priv level */
	.conf_file = CONF_FILE,	/* default config file */
	.prompt = DEFAULT_PROMPT,	/*  default prompt */
};

/* pam cmdline argument parsing */
static int _pam_parse(pam_handle_t * pamh, int argc, CONST char **argv,
		      radius_conf_t * conf)
{
	int ctrl = 0;

	*conf = savconf;	/* initialze from the static config */

	/*
	 *      If either is not there, then we can't parse anything.
	 */
	if ((argc == 0) || (argv == NULL))
		return ctrl;

	/* step through arguments */
	for (ctrl = 0; argc-- > 0; ++argv) {

		/* generic options */
		if (!strncmp(*argv, "conf=", 5)) {
			conf->conf_file = *argv + 5;

		} else if (!strcmp(*argv, "use_first_pass")) {
			ctrl |= PAM_USE_FIRST_PASS;

		} else if (!strcmp(*argv, "try_first_pass")) {
			ctrl |= PAM_TRY_FIRST_PASS;

		} else if (!strcmp(*argv, "skip_passwd")) {
			ctrl |= PAM_SKIP_PASSWD;

		} else if (!strncmp(*argv, "retry=", 6)) {
			conf->retries = atoi(*argv + 6);

		} else if (!strcmp(*argv, "localifdown")) {
			conf->localifdown = 1;

		} else if (!strncmp(*argv, "client_id=", 10)) {
			if (conf->client_id) {
				_pam_log(pamh, LOG_WARNING, "ignoring duplicate"
					 " '%s'", *argv);
			} else {
				conf->client_id = (char *)*argv + 10;	/* point to the client-id */
			}
		} else if (!strcmp(*argv, "accounting_bug")) {
			conf->accounting_bug = TRUE;

		} else if (!strcmp(*argv, "ruser")) {
			ctrl |= PAM_RUSER_ARG;

		} else if (!strcmp(*argv, "debug")) {
			ctrl |= PAM_DEBUG_ARG;
			conf->debug = TRUE;

		} else if (!strncmp(*argv, "prompt=", 7)) {
			if (!strncmp
			    (conf->prompt, (char *)*argv + 7, MAXPROMPT)) {
				_pam_log(pamh, LOG_WARNING,
					 "ignoring duplicate" " '%s'", *argv);
			} else {
				/* truncate excessive prompts to (MAXPROMPT - 3) length */
				if (strlen((char *)*argv + 7) >=
				    (MAXPROMPT - 3)) {
					*((char *)*argv + 7 + (MAXPROMPT - 3)) =
					    0;
				}
				/* set the new prompt */
				memset(conf->prompt, 0, sizeof(conf->prompt));
				snprintf(conf->prompt, MAXPROMPT, "%s: ",
					 (char *)*argv + 7);
			}

		} else if (!strcmp(*argv, "force_prompt")) {
			conf->force_prompt = TRUE;

		} else if (!strncmp(*argv, "max_challenge=", 14)) {
			conf->max_challenge = atoi(*argv + 14);

		} else {
			_pam_log(pamh, LOG_WARNING, "unrecognized option '%s'",
				 *argv);
		}
	}

	return ctrl;
}

/* Callback function used to free the saved return value for pam_setcred. */
static void _int_free(pam_handle_t * pamh, void *x, int error_status)
{
	free(x);
}

/*************************************************************************
 * SMALL HELPER FUNCTIONS
 *************************************************************************/

/* useful for debugging, and maybe some user messages.  */
__attribute__ ((unused))
static char *ai_ntop(const struct sockaddr *sa)
{
	static char server_address[INET6_ADDRSTRLEN + 16];

	switch (sa->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
			  server_address, INET_ADDRSTRLEN);

		snprintf(server_address + strlen(server_address), 14, ":%hu",
			 htons(((struct sockaddr_in *)sa)->sin_port));
		break;

	case AF_INET6:
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
			  server_address, INET6_ADDRSTRLEN);

		snprintf(server_address + strlen(server_address), 14, ":%hu",
			 htons(((struct sockaddr_in6 *)sa)->sin6_port));
		break;

	default:
		strcpy(server_address, "Unknown AF");
	}
	return server_address;
}

/*
 * Return an IP address as a struct sockaddr *.
 */
static int get_ipaddr(char *host, struct sockaddr *addr, char *port)
{
	struct addrinfo hints;
	struct addrinfo *results;
	int r;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_ADDRCONFIG;

	r = getaddrinfo(host, port && port[0] ? port : NULL, &hints, &results);
	if (r == 0) {
		memcpy(addr, results->ai_addr, results->ai_addrlen);
		freeaddrinfo(results);
	}

	return r;
}

/*
 * Lookup server->hostname, to get server->ip
 * Done once when server list parsed.  The last part, the
 * if port isn't set in config, it needs to be set to either
 * radius or raddacct
 * returns 0 on success, otherwise non-zero
 */
static int host2server(pam_handle_t * pamh, radius_server_t * server)
{
	char hostbuffer[256], tmpn[11];
	char *hostname, *portstart, *p, *port = NULL, *portacct = NULL;
	int retval, retvala;

	/* hostname might be [ipv6::address] */
	strncpy(hostbuffer, server->hostname, sizeof(hostbuffer) - 1);
	hostbuffer[sizeof(hostbuffer) - 1] = 0; /* ensure null term */
	hostname = hostbuffer;
	portstart = hostbuffer;
	if (hostname[0] == '[') {
		if ((p = strchr(hostname, ']')) != NULL) {
			hostname++;
			*p++ = 0;
			portstart = p;
		}
	}
	if ((port = strchr(portstart, ':')) != NULL)
		*port++ = '\0';

	/*
	 * Use the configured port if set, otherwise if accounting,
	 * "radacct", else "radius".  If configured port is numeric,
	 * and we are doing accounting, add 1.
	 * if they specified a name, and it's "radius", use "radacct"
	 * for the accounting port.  Otherwise, warn them that we'll
	 * have problems with accounting.
	 */
	if (port) {
		if (isdigit((unsigned char)*port)) {
			int n;
			/*
			 * normal accounting port 1 higher than auth port, so
			 * assume that's true if they gave a numeric
			 * port, and add 1 to it, when doing accounting
			 */
			if (sscanf(port, "%d", &n) == 1) {
				snprintf(tmpn, sizeof(tmpn), "%d", n + 1);
				portacct = tmpn;
			}
		} else {
			portacct = "radacct";
			if (strcmp(port, "radius"))
				_pam_log(pamh, LOG_WARNING, "Server %s uses"
					 " non-standard port '%s', using %s for"
					 " accounting", server->hostname, port,
					 portacct);
		}
	}
	if (!port)
		port = "radius";
	if (!portacct)
		portacct = "radacct";

	server->hostpart = strdup(hostname);
	if (!server->hostpart)
		_pam_log(pamh, LOG_ERR, "Memory allocation error saving"
			 " hostname %s in server %s info: %m", hostname,
			 server->hostname);

	/*  set up sockaddr for sendto calls  */
	server->ip = (struct sockaddr *)&server->ip_storage;
	server->ip_acct = (struct sockaddr *)&server->ipacct_storage;

	retval = get_ipaddr(server->hostpart, server->ip, port);
	if (retval) {
		_pam_log(pamh, LOG_WARNING,
			 "Failed looking up IP address for"
			 " server %s port %s (error=%s)",
			 server->hostpart, port, gai_strerror(retval));
		server->family = AF_INET;	/* assume, for sanity */
	} else
		server->family = server->ip->sa_family;

	retvala = get_ipaddr(server->hostpart, server->ip_acct, portacct);
	if (retvala)
		_pam_log(pamh, LOG_WARNING,
			 "Failed looking up IP address for"
			 " accounting server %s port %s (error=%s)",
			 server->hostpart, portacct, gai_strerror(retval));
	return retval + retvala;
}

/*
 * Do XOR of two buffers.
 */
static unsigned char *xor(unsigned char *p, unsigned char *q, int length)
{
	int i;
	unsigned char *retval = p;

	for (i = 0; i < length; i++) {
		*(p++) ^= *(q++);
	}
	return retval;
}

/**************************************************************************
 * MID-LEVEL RADIUS CODE
 **************************************************************************/

/*
 * get a pseudo-random vector.
 */
static void get_random_vector(unsigned char *vector)
{
#ifdef linux
	int fd = open("/dev/urandom", O_RDONLY);	/* Linux: get *real* random numbers */
	int total = 0;
	if (fd >= 0) {
		while (total < AUTH_VECTOR_LEN) {
			int bytes =
			    read(fd, vector + total, AUTH_VECTOR_LEN - total);
			if (bytes <= 0)
				break;	/* oops! Error */
			total += bytes;
		}
		close(fd);
	}

	if (total != AUTH_VECTOR_LEN)
#endif
	{			/* do this *always* on other platforms */
		MD5_CTX my_md5;
		struct timeval tv;
		struct timezone tz;
		static unsigned int session = 0;	/* make the number harder to guess */

		/* Use the time of day with the best resolution the system can
		   give us -- often close to microsecond accuracy. */
		gettimeofday(&tv, &tz);

		if (session == 0) {
			session = getppid();	/* (possibly) hard to guess information */
		}

		tv.tv_sec ^= getpid() * session++;

		/* Hash things to get maybe cryptographically strong pseudo-random numbers */
		MD5Init(&my_md5);
		MD5Update(&my_md5, (unsigned char *)&tv, sizeof(tv));
		MD5Update(&my_md5, (unsigned char *)&tz, sizeof(tz));
		MD5Final(vector, &my_md5);	/* set the final vector */
	}
}

/*
 * RFC 2139 says to do generate the accounting request vector this way.
 * However, the Livingston 1.16 server doesn't check it.	The Cistron
 * server (http://home.cistron.nl/~miquels/radius/) does, and this code
 * seems to work with it.	It also works with Funk's Steel-Belted RADIUS.
 */
static void get_accounting_vector(AUTH_HDR * request, radius_server_t * server)
{
	MD5_CTX my_md5;
	int secretlen = strlen(server->secret);
	int len = ntohs(request->length);

	memset(request->vector, 0, AUTH_VECTOR_LEN);
	MD5Init(&my_md5);
	memcpy(((char *)request) + len, server->secret, secretlen);

	MD5Update(&my_md5, (unsigned char *)request, len + secretlen);
	MD5Final(request->vector, &my_md5);	/* set the final vector */
}

/*
 * Verify the response from the server
 */
static int verify_packet(char *secret, AUTH_HDR * response, AUTH_HDR * request)
{
	MD5_CTX my_md5;
	unsigned char calculated[AUTH_VECTOR_LEN];
	unsigned char reply[AUTH_VECTOR_LEN];

	/*
	 * We could dispense with the memcpy, and do MD5's of the packet
	 * + vector piece by piece.     This is easier understand, and maybe faster.
	 */
	memcpy(reply, response->vector, AUTH_VECTOR_LEN);	/* save the reply */
	memcpy(response->vector, request->vector, AUTH_VECTOR_LEN);	/* sent vector */

	/* MD5(response packet header + vector + response packet data + secret) */
	MD5Init(&my_md5);
	MD5Update(&my_md5, (unsigned char *)response, ntohs(response->length));

	/*
	 * This next bit is necessary because of a bug in the original Livingston
	 * RADIUS server.       The authentication vector is *supposed* to be MD5'd
	 * with the old password (as the secret) for password changes.
	 * However, the old password isn't used.        The "authentication" vector
	 * for the server reply packet is simply the MD5 of the reply packet.
	 * Odd, the code is 99% there, but the old password is never copied
	 * to the secret!
	 */
	if (*secret) {
		MD5Update(&my_md5, (unsigned char *)secret, strlen(secret));
	}

	MD5Final(calculated, &my_md5);	/* set the final vector */

	/* Did he use the same random vector + shared secret? */
	if (memcmp(calculated, reply, AUTH_VECTOR_LEN) != 0) {
		return FALSE;
	}
	return TRUE;
}

/*
 * Find an attribute in a RADIUS packet.	Note that the packet length
 * is *always* kept in network byte order.
 */
static attribute_t *find_attribute(AUTH_HDR * response, unsigned char type)
{
	attribute_t *attr = (attribute_t *) & response->data;

	int len = ntohs(response->length) - AUTH_HDR_LEN;

	while (attr->attribute != type) {
		if ((len -= attr->length) <= 0) {
			return NULL;	/* not found */
		}
		attr = (attribute_t *) ((char *)attr + attr->length);
	}

	return attr;
}

struct radius_vsa {
	unsigned char vendorid[4];
	unsigned char vendor_type;
	unsigned char vendor_len;
	unsigned char string[1];
};

/* 
 * Find the VSA attribute with the shell:priv-lvl string if present.
 * If present, return the integer value, otherwise return -1.
 */
static int priv_from_vsa(AUTH_HDR * response)
{
	int ret = -1;
	int len = ntohs(response->length) - AUTH_HDR_LEN;
	attribute_t *attr = (attribute_t *) & response->data;
	const char shellpriv[] = "shell:priv-lvl";
	const int slen = strlen(shellpriv);

	while (len > 0) {
		if (attr->attribute == PW_VENDOR_SPECIFIC) {
			struct radius_vsa *v = (struct radius_vsa *)attr->data;
			int j, s;
			j = attr->length - 6;
			if (j < 0)
				j = 0;
			s = slen + 1;
			if (j > s) {
				const char *vsastr = (char *)v->string;
				/*  skip over the '*' or '=' that should follow
				 *  the attrname */
				if (!strncmp(shellpriv, vsastr, slen)) {
					char *e;
					int priv;
					priv = (int)strtol(&vsastr[s], &e, 0);
					if (e > &vsastr[s]) {
						ret = priv;
						break;
					}

				}
			}
		}
		len -= attr->length;
		attr = (attribute_t *) ((char *)attr + attr->length);
	}
	return ret;
}

/*
 * Add an attribute to a RADIUS packet.
 */
static void add_attribute(AUTH_HDR * request, unsigned char type,
			  CONST unsigned char *data, int length)
{
	attribute_t *p;

	p = (attribute_t *) ((unsigned char *)request + ntohs(request->length));
	p->attribute = type;
	p->length = length + 2;	/* the total size of the attribute */
	request->length = htons(ntohs(request->length) + p->length);
	memcpy(p->data, data, length);
}

/*
 * Add an integer attribute to a RADIUS packet.
 */
static void add_int_attribute(AUTH_HDR * request, unsigned char type, int data)
{
	int value = htonl(data);

	add_attribute(request, type, (unsigned char *)&value, sizeof(int));
}

static void add_nas_ip_address(AUTH_HDR * request, char *hostname)
{
	struct addrinfo hints;
	struct addrinfo *ai;
	int v4seen = 0, v6seen = 0;
	int r;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_ADDRCONFIG;

	r = getaddrinfo(hostname, NULL, &hints, &ai);
	if (r != 0)
		return;

	while (ai != NULL) {
		if (!v4seen && ai->ai_family == AF_INET) {
			v4seen = 1;
			r = ((struct sockaddr_in *)
			     ai->ai_addr)->sin_addr.s_addr;
			add_int_attribute(request, PW_NAS_IP_ADDRESS, ntohl(r));
		}
		if (!v6seen && ai->ai_family == AF_INET6) {
			v6seen = 1;
			add_attribute(request, PW_NAS_IPV6_ADDRESS,
				      (unsigned char *)&((struct sockaddr_in6 *)
						 ai->ai_addr)->sin6_addr, 16);
		}
		ai = ai->ai_next;
	}
	freeaddrinfo(ai);
}

/*
 * Add a RADIUS password attribute to the packet.	Some magic is done here.
 *
 * If it's an PW_OLD_PASSWORD attribute, it's encrypted using the encrypted
 * PW_PASSWORD attribute as the initialization vector.
 *
 * If the password attribute already exists, it's over-written.	This allows
 * us to simply call add_password to update the password for different
 * servers.
 */
static void add_password(AUTH_HDR * request, unsigned char type,
			 CONST char *password, char *secret)
{
	MD5_CTX md5_secret, my_md5;
	unsigned char misc[AUTH_VECTOR_LEN];
	int i;
	int length = strlen(password);
	unsigned char hashed[256 + AUTH_PASS_LEN];	/* can't be longer than this */
	unsigned char *vector;
	attribute_t *attr;

	if (length > MAXPASS) {	/* shorten the password for now */
		length = MAXPASS;
	}

	memcpy(hashed, password, length);
	memset(hashed + length, 0, sizeof(hashed) - length);

	if (length == 0) {
		length = AUTH_PASS_LEN;	/* 0 maps to 16 */
	}
	if ((length & (AUTH_PASS_LEN - 1)) != 0) {
		length += (AUTH_PASS_LEN - 1);	/* round it up */
		length &= ~(AUTH_PASS_LEN - 1);	/* chop it off */
	}
	/* 16*N maps to itself */
	attr = find_attribute(request, PW_PASSWORD);

	if (type == PW_PASSWORD) {
		vector = request->vector;
	} else {
		vector = attr->data;	/* attr CANNOT be NULL here. */
	}

	/* ************************************************************ */
	/* encrypt the password */
	/* password : e[0] = p[0] ^ MD5(secret + vector) */
	MD5Init(&md5_secret);
	MD5Update(&md5_secret, (unsigned char *)secret, strlen(secret));
	my_md5 = md5_secret;	/* so we won't re-do the hash later */
	MD5Update(&my_md5, vector, AUTH_VECTOR_LEN);
	MD5Final(misc, &my_md5);	/* set the final vector */
	xor(hashed, misc, AUTH_PASS_LEN);

	/* For each step through, e[i] = p[i] ^ MD5(secret + e[i-1]) */
	for (i = 1; i < (length >> 4); i++) {
		my_md5 = md5_secret;	/* grab old value of the hash */
		MD5Update(&my_md5, &hashed[(i - 1) * AUTH_PASS_LEN],
			  AUTH_PASS_LEN);
		MD5Final(misc, &my_md5);	/* set the final vector */
		xor(&hashed[i * AUTH_PASS_LEN], misc, AUTH_PASS_LEN);
	}

	if (type == PW_OLD_PASSWORD) {
		attr = find_attribute(request, PW_OLD_PASSWORD);
	}

	if (!attr) {
		add_attribute(request, type, hashed, length);
	} else {
		memcpy(attr->data, hashed, length);	/* overwrite the packet */
	}
}

/*  called from _pam_end() via pam_set_data() arg to cleanup memory and fd's */
static void cleanup_conf(pam_handle_t * pamh, void *arg, int unused)
{
	radius_server_t *next, *server;

	for (server = (radius_server_t *) arg; server; server = next) {
		if (server->sockfd != -1) {
			close(server->sockfd);
			server->sockfd = -1;
		}
		next = server->next;
		_pam_forget(server->secret);
		_pam_drop(server->port);
		_pam_drop(server->hostname);
		_pam_drop(server->hostpart);
		_pam_drop(server);
	}
}

/*
 * Parse the config file (not the PAM cmdline args)
 * Only do once, since all the entry points call this.  _pam_parse
 * has to be done per entry point, because it can have command line
 * args that are different, but the config file only needs to be read
 * once (again, except for the very rare case of different config files
 * being specified in the PAM lines, which the stat check will catch).
 *
 * Returns  0 if parsed and OK
 * Returns  1 if file already parsed and no change in mtime
 * Returns -1 if errors
*/
static int parse_conffile(pam_handle_t * pamh, radius_conf_t * cf)
{
	static struct stat last_st;
	int line = 0, timeout, ret = 0;
	const char *cfname = cf->conf_file;
	char *p;
	radius_server_t *server = NULL, *tmp;
	FILE *fserver;
	char hostname[BUFFER_SIZE], secret[BUFFER_SIZE], buffer[BUFFER_SIZE];
	char srcip[BUFFER_SIZE];

	if (!cfname || !*cfname) {
		ret = -1;
		goto done;
	}

	if (last_st.st_ino) {
		struct stat st;
		int rst;
		rst = stat(cfname, &st);
		if (!rst && st.st_ino == last_st.st_ino && st.st_mtime ==
		    last_st.st_mtime && st.st_ctime == last_st.st_ctime) {
			/* no changes to savconf, so just return */
			return 1;
		}
	}

	if (cf->server)	{ /* we already had sockets open and bound, cleanup */
		pam_set_data(pamh, "rad_conf_cleanup", NULL, NULL);
		cf->server = NULL; /* in case reuse and no servers found */
	}

	/* the first time around, read the configuration file */
	if ((fserver = fopen(cfname, "r")) == (FILE *) NULL) {
		_pam_log(pamh, LOG_ERR, "Could not open configuration file %s:"
			 " %m", cfname);
		ret = -1;
		goto done;
	}

	while (!feof(fserver) &&
	       (fgets(buffer, sizeof(buffer), fserver) != (char *)NULL) &&
	       (!ferror(fserver))) {
		int scancnt;

		line++;
		p = buffer;

		/* Skip leading whitespace */
		while ((*p == ' ') || (*p == '\t'))
			p++;

		/* Skip blank lines and comments.  */
		if ((*p == '\r') || (*p == '\n') || (*p == '#'))
			continue;

		/* Error out if the text is too long.  */
		if (!*p) {
			_pam_log(pamh, LOG_ERR, "ERROR reading %s, line %d:"
				 " Line too long", cfname, line);
			break;
		}

		srcip[0] = '\0';
		scancnt =
		    sscanf(p, "%s %s %d %s", hostname, secret, &timeout, srcip);

		if (!strcmp(hostname, "vrf-name")) {
			/* is it the name of a vrf we should bind to? */
			if (scancnt < 2)
				_pam_log(pamh, LOG_ERR,
					 "ERROR reading %s, line %d:"
					 " only %d fields", cf->conf_file, line,
					 scancnt);
			else
				snprintf(cf->vrfname, sizeof cf->vrfname, "%s",
					 secret);
			snprintf(savconf.vrfname, sizeof savconf.vrfname,
				 "%s", secret);
			continue;
		} else if (!strcmp(hostname, "priv-lvl")) {
			/* privilege level for privileged logins */
			if (scancnt < 2)
				_pam_log(pamh, LOG_ERR, "ERROR reading %s, line"
					 " %d: only %d fields", cfname, line,
					 scancnt);
			else {
				unsigned long val;
				char *ok;
				val = strtoul(secret, &ok, 0);
				if (ok == secret || val > 15UL ||
				    (*ok && !isspace(*ok)))
					_pam_log(pamh, LOG_ERR, "Invalid number"
						 " (%s) \"%s\" in %s line %d:",
						 secret, hostname, cfname,
						 line);
				else {
					cf->min_priv_lvl = (unsigned)val;
					savconf.min_priv_lvl = cf->min_priv_lvl;
				}
			}
			continue;
		} else if (!strcmp(hostname, "mapped_priv_user")) {
			/* mapped account name of radius privileged user for
			 * uid/auid fixup */
			if (scancnt < 2)
				_pam_log(pamh, LOG_ERR,
					 "ERROR reading %s, line %d:"
					 " only %d fields", cf->conf_file, line,
					 scancnt);
			else
				snprintf(cf->privusrmap, sizeof cf->privusrmap, "%s",
					 secret);
			snprintf(savconf.privusrmap, sizeof savconf.privusrmap,
				 "%s", secret);
			continue;
		} else if (!strcmp(hostname, "debug")) {
			/* allow setting debug in config file as well */
			cf->debug = cfg_debug = 1;
			continue;
		}

		if (scancnt < 2) {
			_pam_log(pamh, LOG_ERR, "ERROR reading %s, line %d:"
				 " only %d fields", cfname, line, scancnt);
			continue;	/* invalid line */
		}
		if (scancnt < 3)
			timeout = 3;	/*  default timeout */

		/* read it in and save the data */
		tmp = calloc(sizeof(radius_server_t), 1);
		if (!tmp) {
			_pam_log(pamh, LOG_ERR,
				 "Unable to allocate server info for %s: %m",
				 hostname);
			ret = -1;
			goto done;
		}
		tmp->sockfd = -1;	/* mark as uninitialized */
		if (server) {
			server->next = tmp;
			server = server->next;
		} else {
			cf->server = tmp;
			server = tmp;	/* first time */
		}

		if (srcip[0])
			snprintf(server->src_ip, sizeof server->src_ip, "%s",
				 srcip);

		server->hostname = strdup(hostname);
		server->secret = strdup(secret);
		if (!server->hostname || !server->secret)
			_pam_log(pamh, LOG_ERR, "Memory allocation error saving"
				 " server %s info: %m", hostname);

		if ((timeout < 1) || (timeout > 60))
			server->timeout = 3;
		else
			server->timeout = timeout;
		server->next = NULL;

	}
	fclose(fserver);

	/*  save config file info for test on multiple calls */
	if (stat(cfname, &last_st) == -1)
		_pam_log(pamh, LOG_ERR, "Error stat'ing config file %s: %m",
			 cfname);

	if (!cf->server) {	/* no server found, die a horrible death */
		_pam_log(pamh, LOG_ERR, "No server found in"
			 " configuration file %s", cf->conf_file);
		ret = -1;
	}

	/*
	 * save the server in savconf for next call (if any) to _parse_args()
	 * for the same config file (will be overridden if a different config
	 * file; need to do that even if NULL, so we don't re-use old bad data
	 */
done:
	savconf.server = cf->server;

	return ret;
}

static int setup_sock(pam_handle_t * pamh, radius_server_t * server,
		      radius_conf_t * conf)
{
	struct sockaddr_storage nullip;
	struct sockaddr *addr;
	char *hname;
	size_t sockaddrsz;
	int debug = conf->debug;

	if (host2server(pamh, server))
		return 1;

	memset(&nullip, 0, sizeof nullip);
	addr = (struct sockaddr *)&nullip;
	if (server->src_ip[0]) {
		int r;
		/*  bind to specified source IP and family */
		hname = server->src_ip;
		r = get_ipaddr(hname, addr, NULL);
		if (r)
			_pam_log(pamh, LOG_WARNING,
				 "Failed looking up source IP address %s for"
				 " server %s (error=%s)",
				 server->src_ip, server->hostname,
				 gai_strerror(r));
	} else
		hname = server->hostpart;

	addr->sa_family = server->family;

	server->sockfd = socket(server->family, SOCK_DGRAM, 0);
	if (server->sockfd == -1) {
		_pam_log(pamh, LOG_WARNING, "Failed to open socket for"
			 " %s: %m", server->hostname);
		return 1;
	}

	/*  warn only, not fatal */
	if (fcntl(server->sockfd, F_SETFD, FD_CLOEXEC))
		_pam_log(pamh, LOG_WARNING, "Set sockets close on exec failed"
			 " for %s: %m", server->hostname);

#ifndef HAVE_POLL_H
	if (server->sockfd >= FD_SETSIZE) {
		_pam_log(pamh, LOG_ERR, "Unusable socket, FD is larger than"
			 " %d", FD_SETSIZE);
		close(server->sockfd);
		server->sockfd = -1;
		return 1;
	}
#endif
	sockaddrsz = server->family == AF_INET ? sizeof(struct sockaddr_in) :
	    sizeof(struct sockaddr_in6);

	if (bind(server->sockfd, addr, sockaddrsz) < 0) {
		_pam_log(pamh, LOG_ERR, "Bind for server %s failed: %m", hname);
		/*  mark sockfd as not usable, by closing and set to -1 */
		close(server->sockfd);
		server->sockfd = -1;
		return 1;
	}

	if (conf->vrfname[0]) {
		/*  do not fail if the bind fails, connection may succeed */
		if (setsockopt(server->sockfd, SOL_SOCKET, SO_BINDTODEVICE,
			       conf->vrfname,
			       strlen(conf->vrfname) + 1) == -1) {
			_pam_log(pamh, LOG_WARNING,
				 "Binding host %s socket to VRF %s"
				 " failed: %m", server->hostname,
				 conf->vrfname);
		}
		DPRINT(pamh, LOG_DEBUG, "Configured server %s vrf as: %s",
		       server->hostname, conf->vrfname);
	}
	return 0;
}

/*
 * allocate and open a local port for communication with the RADIUS
 * server.
 * The server connection only needs to be redone if there are arguments,
 * and they are different (rare).
 */
static int initialize(pam_handle_t * pamh, radius_conf_t * conf)
{
	int parse, retsetup, nservers = 0;
	const int rfail = PAM_AUTHINFO_UNAVAIL;
	radius_server_t *server = NULL;

	parse = parse_conffile(pamh, conf);
	if (parse == -1)
		return rfail;

	/*  setup the sockets, bind to them, etc. */
	for (server = conf->server; server; server = server->next) {
		retsetup = setup_sock(pamh, server, conf);
		if (retsetup == PAM_SUCCESS)
			nservers++;
	}

	retsetup = nservers ? PAM_SUCCESS : rfail;

	if (parse != 1) { /*  only on first call */
		if (!nservers)
			_pam_log(pamh, LOG_ERR, "No valid server found in"
				 " configuration file %s", conf->conf_file);
		else {
			cleaned_up = 0;
			pam_set_data(pamh, "rad_conf_cleanup",
				     (void *)conf->server, cleanup_conf);
		}
	}

	return retsetup;
}

/*
 * Helper function for building a radius packet.
 * It initializes *some* of the header, and adds common attributes.
 */
static void build_radius_packet(AUTH_HDR * request, CONST char *user,
				CONST char *password, radius_conf_t * conf)
{
	char hostname[256];

	hostname[0] = '\0';
	gethostname(hostname, sizeof(hostname) - 1);

	request->length = htons(AUTH_HDR_LEN);

	if (password) {		/* make a random authentication req vector */
		get_random_vector(request->vector);
	}

	add_attribute(request, PW_USER_NAME, (unsigned char *)user,
		      strlen(user));

	/*
	 *      Add a password, if given.
	 */
	if (password) {
		add_password(request, PW_PASSWORD, password,
			     conf->server->secret);

		/*
		 *      Add a NULL password to non-accounting requests.
		 */
	} else if (request->code != PW_ACCOUNTING_REQUEST) {
		add_password(request, PW_PASSWORD, "", conf->server->secret);
	}

	/* Perhaps add NAS IP Address (and v6 version) */
	/* Add possibility use source-ip-address as NAS-IP-Address */
	if (conf->server->src_ip && strlen(conf->server->src_ip) > 0)
		add_nas_ip_address(request, conf->server->src_ip);
	else
		add_nas_ip_address(request, hostname);

	/* There's always a NAS identifier */
	if (conf->client_id && *conf->client_id) {
		add_attribute(request, PW_NAS_IDENTIFIER,
			      (unsigned char *)conf->client_id,
			      strlen(conf->client_id));
	}

	/*
	 *      Add in the port (pid) and port type (virtual).
	 *
	 *      We might want to give the TTY name here, too.
	 */
	add_int_attribute(request, PW_NAS_PORT_ID, getpid());
	add_int_attribute(request, PW_NAS_PORT_TYPE, PW_NAS_PORT_TYPE_VIRTUAL);
}

/*
 * Talk RADIUS to a server.
 * Send a packet and get the response
 */
static int talk_radius(radius_conf_t * conf, AUTH_HDR * request,
		       AUTH_HDR * response, char *password, char *old_password,
		       int tries, pam_handle_t * pamh, int accounting)
{
	int total_length;
#ifdef HAVE_POLL_H
	struct pollfd pollfds[1];
#else
	fd_set set;
#endif
	struct timeval tv;

	time_t now, end;
	int rcode;
	radius_server_t *server = conf->server;
	int ok;
	int server_tries;
	int retval;
	int sockfd;

	/* ************************************************************ */
	/* Now that we're done building the request, we can send it */

	/*
	   Hmm... on password change requests, all of the found server information
	   could be saved with a pam_set_data(), which means even the radius_conf_t
	   information will have to be malloc'd at some point

	   On the other hand, we could just try all of the servers again in
	   sequence, on the off chance that one may have ended up fixing itself.
	 */

	/* loop over all available servers */
	while (server != NULL) {
		sockfd = server->sockfd;
		struct sockaddr *addr =
		    accounting ? server->ip_acct : server->ip;

		if (sockfd == -1) {
			ok = FALSE;
			goto next;	/*  try next server, if any */
		}

		/* clear the response */
		memset(response, 0, sizeof(AUTH_HDR));

		if (!password) {	/* make an RFC 2139 p6 request authenticator */
			get_accounting_vector(request, server);
		}

		total_length = ntohs(request->length);
		server_tries = tries;
 send:
		/* send the packet */
		if (sendto(sockfd, (char *)request, total_length, 0,
			   addr, sizeof(struct sockaddr_storage)) < 0) {
			_pam_log(pamh, LOG_ERR, "Error sending packet to"
				 " server %s: %m", server->hostname);
			ok = FALSE;
			goto next;	/* skip to the next server */
		}

		/* ************************************************************ */
		/* Wait for the response, and verify it. */
		time(&now);

		tv.tv_sec = server->timeout;	/* wait for the specified time */
		tv.tv_usec = 0;
		end = now + tv.tv_sec;

#ifdef HAVE_POLL_H
		pollfds[0].fd = sockfd;	/* wait only for the RADIUS UDP socket */
		pollfds[0].events = POLLIN;	/* wait for data to read */
#else
		FD_ZERO(&set);	/* clear out the set */
		FD_SET(sockfd, &set);	/* wait only for the RADIUS UDP socket */
#endif

		/* loop, waiting for the network to return data */
		ok = TRUE;
		while (ok) {
#ifdef HAVE_POLL_H
			rcode =
			    poll((struct pollfd *)&pollfds, 1,
				 tv.tv_sec * 1000);
#else
			rcode = select(sockfd + 1, &set, NULL, NULL, &tv);
#endif

			/* timed out */
			if (rcode == 0) {
				if (--server_tries) {
					_pam_log(pamh, LOG_WARNING, "server %s"
						 " no reponse, retrying",
						 server->hostname);
					goto send;
				}
				_pam_log(pamh, LOG_ERR, "server %s"
					 " failed to respond",
					 server->hostname);
				ok = FALSE;
				break;	/* exit from the loop */
			} else if (rcode < 0) {

				/* poll returned an error */
				if (errno == EINTR) {	/* we were interrupted */
					time(&now);

					if (now > end) {
						_pam_log(pamh, LOG_ERR,
							 "server %s "
							 "failed to respond",
							 server->hostname);
						if (--server_tries)
							goto send;
						ok = FALSE;
						break;	/* exit from the loop */
					}

					tv.tv_sec = end - now;
					if (tv.tv_sec == 0) {	/* keep waiting */
						tv.tv_sec = 1;
					}
				} else {	/* a real error */
					_pam_log(pamh, LOG_ERR, "Error waiting"
						 " for response from"
						 " server %s: %m",
						 server->hostname);
					ok = FALSE;
					break;
				}
			} else	/* the poll/select  returned OK */
#ifdef HAVE_POLL_H
			if (pollfds[0].revents & POLLIN)
#else
			if (FD_ISSET(sockfd, &set))
#endif
			{

				/* try to receive some data */
				if ((total_length =
				     recvfrom(sockfd, (void *)response,
					      BUFFER_SIZE, 0, NULL,
					      NULL)) < 0) {
					_pam_log(pamh, LOG_ERR,
						 "error reading"
						 "response from server"
						 " %s: %m", server->hostname);
					ok = FALSE;
					break;

					/* there's data, see if it's valid */
				} else {
					char *p = server->secret;

					if ((ntohs(response->length) !=
					     total_length)
					    || (ntohs(response->length) >
						BUFFER_SIZE)) {
						_pam_log(pamh, LOG_ERR,
							 "response from "
							 "server %s is "
							 "corrupted",
							 server->hostname);
						ok = FALSE;
						break;
					}

					/* Check if we have the data OK.
					 * We should also check request->id */
					if (password) {
						if (old_password) {
#ifdef LIVINGSTON_PASSWORD_VERIFY_BUG_FIXED
							/* what it should be */
							p = old_password;
#else
							/* what it really is */
							p = "";
#endif
						}
						/*
						 * RFC 2139 p.6 says not do do this, but
						 * the Livingston 1.16 server disagrees.
						 * If the user says he wants the bug,
						 * give in.
						 */
					} else { /* authentication request */
						if (conf->accounting_bug) {
							p = "";
						}
					}

					if (!verify_packet
					    (p, response, request)) {
						_pam_log(pamh, LOG_ERR,
							 "response from server"
							 " %s failed"
							 " verification:"
							 " The shared secret is"
							 " probably incorrect.",
							 server->hostname);
						ok = FALSE;
						break;
					}

					/*
					 * Check that the response ID matches
					 * the request ID.
					 */
					if (response->id != request->id) {
						_pam_log(pamh, LOG_WARNING,
							 "Response packet ID %d"
							 " does not match the"
							 " request packet ID"
							 " %d: verification of"
							 " packet fails",
							 response->id,
							 request->id);
						ok = FALSE;
						break;
					}
				}

				/*
				 * Whew! The poll is done. It hasn't timed out,
				 * or errored out.  It's our descriptor.
				 * We've got some data. It's the right size.
				 * The packet is valid.  NOW, we can skip out of
				 * the loop, and process the packet
				 */
				break;
			}
			/* otherwise, we've got data on another descriptor, keep
			 * checking the network */
		}
 next:				/* go to the next server if this one didn't respond */
		if (ok)
			break;
		server = server->next;
		if (server) {	/* if there's more servers to check */
			/* get a new authentication vector, and update
			 * the passwords */
			get_random_vector(request->vector);
			request->id = request->vector[0];

			/* update passwords, as appropriate */
			if (password) {
				get_random_vector(request->vector);
				if (old_password) {
					/* password change request */
					add_password(request,
						     PW_PASSWORD,
						     password, old_password);
					add_password(request,
						     PW_OLD_PASSWORD,
						     old_password,
						     old_password);
				} else {	/* authentication request */
					add_password(request,
						     PW_PASSWORD,
						     password, server->secret);
				}
			}
		}
	}

	if (!server) {
		_pam_log(pamh, LOG_ERR, "All RADIUS servers failed to respond");
		if (conf->localifdown)
			retval = PAM_IGNORE;
		else
			retval = PAM_AUTHINFO_UNAVAIL;
	} else
		retval = PAM_SUCCESS;

	return retval;
}

/**************************************************************************
 * MIDLEVEL PAM CODE
 **************************************************************************/

/* this is our front-end for module-application conversations */

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) { return retval; }

static int rad_converse(pam_handle_t * pamh, int msg_style, char *message,
			char **password)
{
	CONST struct pam_conv *conv;
	struct pam_message resp_msg;
	CONST struct pam_message *msg;
	struct pam_response *resp = NULL;
	int retval;

	resp_msg.msg_style = msg_style;
	resp_msg.msg = message;
	msg = &resp_msg;

	/* grab the password */
	retval = pam_get_item(pamh, PAM_CONV, (CONST void **)&conv);
	PAM_FAIL_CHECK;

	retval = conv->conv(1, &msg, &resp, conv->appdata_ptr);
	PAM_FAIL_CHECK;

	if (password) {		/* assume msg.type needs a response */
		/* I'm not sure if this next bit is necessary on Linux */
#ifdef sun
		/* NULL response, fail authentication */
		if ((resp == NULL) || (resp->resp == NULL)) {
			return PAM_SYSTEM_ERR;
		}
#endif

		*password = resp->resp;
		free(resp);
	}

	return PAM_SUCCESS;
}

/*
 *	We'll create the home directory if needed, and we'll write the flat file
 *	mapping entry.  It's done at this point, because this is the end of the
 *	authentication phase (and authorization, too, since authorization is
 *	part of *	authentication phase for RADIUS) for ssh, login, etc.
 */
static void
setup_userinfo(pam_handle_t * pamh, radius_conf_t *cfg, const char *user,
	       int debug, int privileged)
{
	struct passwd *pw;

	/*
	 * set SUDO_PROMPT in env so that it prompts as the login user, not the
	 * mapped * user, unless (unlikely) the prompt has already been set.
	 * It won't hurt to do this if the user wasn't mapped.
	 */
	if (!pam_getenv(pamh, "SUDO_PROMPT")) {
		char nprompt[strlen("SUDO_PROMPT=[sudo] password for ") +
			strlen(user) + 3];	/* + 3 for ": " and the \0 */
		snprintf(nprompt, sizeof nprompt,
			 "SUDO_PROMPT=[sudo] password for %s: ", user);
		if (pam_putenv(pamh, nprompt) != PAM_SUCCESS)
			_pam_log(pamh, LOG_NOTICE,
				 "failed to set PAM sudo prompt " "(%s)",
				 nprompt);
	}
	pw = getpwnam(user);	/* this should never fail, at this point... */
	if (!pw) {
		if (debug)
			pam_syslog(pamh, LOG_DEBUG,
				   "Failed to get homedir for user (%s)", user);
		return;
	}

	/*
	 * because the RADIUS protocol is single pass, we always have the
	 * pw_uid of the unprivileged account at this point.  Set things up
	 * so we use the uid of the privileged radius account.
	 */
	if (privileged) {
		struct passwd *pwp;
		if (!cfg->privusrmap[0] || !(pwp = getpwnam(cfg->privusrmap))) {
			_pam_log(pamh, LOG_WARNING, "Failed to find uid for"
				 " privileged account %s, uid may be wrong"
				 " for user %s",
				 cfg->privusrmap[0] ? cfg->privusrmap :
				 "(unset in config)", user);
		}
		else if (pwp && pw->pw_uid != pwp->pw_uid) {
	syslog(LOG_DEBUG, "OLSON wrmap user=%s, but uid=%u, change to %u",
	       user, pw->pw_uid, pwp->pw_uid);
		pw->pw_uid = pwp->pw_uid;
		}
	}

	/*
	 * We don't "fail" on errors here, since they are not fatal for
	 * the session, although they can result in name or uid lookups not
	 * working correctly.
	 */
	__write_mapfile(pamh, user, pw->pw_uid, privileged, debug);
	__chk_homedir(pamh, user, pw->pw_dir, debug);
}

/*  this is used so that sm_auth returns an appropriate value */
static void inline setcred_return(pam_handle_t * pamh, int val)
{
	int *pret = malloc(sizeof(int));
	*pret = val;
	pam_set_data(pamh, "rad_setcred_return", (void *)pret, _int_free);
}

/**************************************************************************
 * GENERAL CODE
 **************************************************************************/

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) { \
    goto do_next; }

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc,
				   CONST char **argv)
{
	CONST char *user;
	CONST char *userinfo;
	char *password = NULL;
	CONST char *rhost;
	char *resp2challenge = NULL;
	int ctrl, debug = 0;
	int retval = PAM_AUTH_ERR;
	int num_challenge = 0;

	char recv_buffer[4096];
	char send_buffer[4096];
	AUTH_HDR *request = (AUTH_HDR *) send_buffer;
	AUTH_HDR *response = (AUTH_HDR *) recv_buffer;
	radius_conf_t config;

	ctrl = _pam_parse(pamh, argc, argv, &config);

	/*
	 * Get the IP address of the authentication server
	 * Then, open a socket, and bind it to a port
	 * Called early, so we can set debug flag
	 */
	retval = initialize(pamh, &config);
	PAM_FAIL_CHECK;

	debug = config.debug + cfg_debug;

	/* grab the user name */
	retval = pam_get_user(pamh, &user, NULL);
	PAM_FAIL_CHECK;

	/* check that they've entered something, and not too long, either */
	if (user == NULL || (strlen(user) > MAXPWNAM)) {
		retval = PAM_USER_UNKNOWN;
		DPRINT(pamh, LOG_DEBUG, "User name was NULL, or too long");
	}
	PAM_FAIL_CHECK;

	if (ctrl & PAM_RUSER_ARG) {
		retval =
		    pam_get_item(pamh, PAM_RUSER, (CONST void **)&userinfo);
		PAM_FAIL_CHECK;
		DPRINT(pamh, LOG_DEBUG, "Got PAM_RUSER name %s", userinfo);

		if (!strcmp("root", user)) {
			user = userinfo;
			DPRINT(pamh, LOG_DEBUG, "Username now %s from ruser",
			       user);
		} else {
			DPRINT(pamh, LOG_DEBUG,
			       "Skipping ruser for non-root auth");
		}
	}

	/*
	 * If there's no client id specified, use the service type, to help
	 * keep track of which service is doing the authentication.
	 */
	if (!config.client_id) {
		retval =
		    pam_get_item(pamh, PAM_SERVICE,
				 (CONST void **)&config.client_id);
		PAM_FAIL_CHECK;
	}

	/* build and initialize the RADIUS packet */
	request->code = PW_AUTHENTICATION_REQUEST;
	get_random_vector(request->vector);
	request->id = request->vector[0];	/* this should be evenly distributed */

	/* grab the password (if any) from the previous authentication layer */
	if (!config.force_prompt) {
		DPRINT(pamh, LOG_DEBUG, "ignore last_pass, force_prompt set");
		retval =
		    pam_get_item(pamh, PAM_AUTHTOK, (CONST void **)&password);
		PAM_FAIL_CHECK;
	}

	if (password) {
		password = strdup(password);
		DPRINT(pamh, LOG_DEBUG, "Got password %s", password);
	}

	/* no previous password: maybe get one from the user */
	if (!password) {
		if (ctrl & PAM_USE_FIRST_PASS) {
			retval = PAM_AUTH_ERR;	/* use one pass only, stopping if it fails */
			goto do_next;
		}

		/* check to see if we send a NULL password the first time around */
		if (!(ctrl & PAM_SKIP_PASSWD)) {
			retval = rad_converse(pamh, PAM_PROMPT_ECHO_OFF,
					      config.prompt, &password);
			PAM_FAIL_CHECK;

		} else {
			password = strdup("");
		}
	}
	/* end of password == NULL */
	build_radius_packet(request, user, password, &config);
	/* not all servers understand this service type, but some do */
	add_int_attribute(request, PW_USER_SERVICE_TYPE, PW_AUTHENTICATE_ONLY);

	/*
	 *      Tell the server which host the user is coming from.
	 *
	 *      Note that this is NOT the IP address of the machine running PAM!
	 *      It's the IP address of the client.
	 */
	retval = pam_get_item(pamh, PAM_RHOST, (CONST void **)&rhost);
	PAM_FAIL_CHECK;
	if (rhost) {
		add_attribute(request, PW_CALLING_STATION_ID,
			      (unsigned char *)rhost, strlen(rhost));
	}

	DPRINT(pamh, LOG_DEBUG, "Sending request code %d", request->code);

	retval = talk_radius(&config, request, response, password, NULL,
			     config.retries + 1, pamh, 0);
	PAM_FAIL_CHECK;

	DPRINT(pamh, LOG_DEBUG, "Got response code %d", response->code);

	/*
	 *      If we get an authentication failure, and we sent a NULL password,
	 *      ask the user for one and continue.
	 *
	 *      If we get an access challenge, then do a response, for as many
	 *      challenges as we receive.
	 */
	while (response->code == PW_ACCESS_CHALLENGE) {
		attribute_t *a_state, *a_reply;
		char challenge[BUFFER_SIZE];

		/* Now we do a bit more work: challenge the user, and get a response */
		if (((a_state = find_attribute(response, PW_STATE)) == NULL) ||
		    ((a_reply =
		      find_attribute(response, PW_REPLY_MESSAGE)) == NULL)) {
			/* Actually, State isn't required. */
			_pam_log(pamh, LOG_ERR, "Access-Challenge"
				 " received with State or Reply-Message"
				 " missing");
			retval = PAM_AUTHINFO_UNAVAIL;
			goto do_next;
		}

		/*
		 *      Security fixes.
		 */
		if ((a_state->length <= 2) || (a_reply->length <= 2)) {
			_pam_log(pamh, LOG_ERR, "Access-Challenge"
				 " received with invalid State or"
				 " Reply-Message");
			retval = PAM_AUTHINFO_UNAVAIL;
			goto do_next;
		}

		memcpy(challenge, a_reply->data, a_reply->length - 2);
		challenge[a_reply->length - 2] = 0;

		/* It's full challenge-response, we should have echo on */
		retval = rad_converse(pamh, PAM_PROMPT_ECHO_ON, challenge,
				      &resp2challenge);
		PAM_FAIL_CHECK;

		/* now that we've got a response, build a new radius packet */
		build_radius_packet(request, user, resp2challenge, &config);
		/* request->code is already PW_AUTHENTICATION_REQUEST */
		request->id++;	/* one up from the request */

		if (rhost) {
			add_attribute(request, PW_CALLING_STATION_ID,
				      (unsigned char *)rhost, strlen(rhost));
		}

		/* copy the state over from the servers response */
		add_attribute(request, PW_STATE, a_state->data,
			      a_state->length - 2);

		retval = talk_radius(&config, request, response,
				     resp2challenge, NULL, 1, pamh, 0);
		PAM_FAIL_CHECK;

		DPRINT(pamh, LOG_DEBUG, "Got response to challenge code %d",
		       response->code);

		/*
		 * max_challenge limits the # of challenges a server can issue
		 * It's a workaround for buggy servers
		 */
		if (config.max_challenge > 0
		    && response->code == PW_ACCESS_CHALLENGE) {
			num_challenge++;
			if (num_challenge >= config.max_challenge) {
				DPRINT(pamh, LOG_DEBUG,
				       "maximum number of challenges (%d)"
				       " reached, failing", num_challenge);
				break;
			}
		}
	}

	/* Whew! Done the pasword checks, look for an authentication acknowledge */
	if (response->code == PW_AUTHENTICATION_ACK) {
		int privlvl;

		/*
		 * get the privilege level via VSA, if present, and save it for the
		 *  accounting entry point
		 */
		privlvl = priv_from_vsa(response);
		if (debug) {
			if (privlvl < 0)
				_pam_log(pamh, LOG_NOTICE,
					 "server did not return VSA"
					 "with shell:priv-lvl");
			else
				_pam_log(pamh, LOG_NOTICE,
					 "server VSA shell:priv-lvl"
					 "=%d, min for priv=%d", privlvl,
					 config.min_priv_lvl);
		}
		setup_userinfo(pamh, &config, user, debug,
			       privlvl >= config.min_priv_lvl);
		retval = PAM_SUCCESS;
	} else {
		retval = PAM_AUTH_ERR;	/* authentication failure */
	}

 do_next:
	/* If there was a password pass it to the next layer */
	if (password && *password) {
		pam_set_item(pamh, PAM_AUTHTOK, password);
	}

	DPRINT(pamh, LOG_DEBUG, "authentication %s",
	       retval == PAM_SUCCESS ? "succeeded" : "failed");

	_pam_forget(password);
	_pam_forget(resp2challenge);
	setcred_return(pamh, retval);
	return retval;
}

/*
 * Return a value matching the return value of pam_sm_authenticate, for
 * greatest compatibility.
 * (Always returning PAM_SUCCESS breaks other authentication modules;
 * always returning PAM_IGNORE breaks PAM when we're the only module.)
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc,
			      CONST char **argv)
{
	int ret, retval, *pret = NULL;

	retval = PAM_SUCCESS;
	ret = pam_get_data(pamh, "rad_setcred_return", (CONST void **)&pret);
	return ret == PAM_SUCCESS && pret ? *pret : retval;
}

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) {goto error; }

/* handle the accounting */
static int pam_private_session(pam_handle_t * pamh, int flags, int argc,
			       CONST char **argv, int status)
{
	CONST char *user;
	CONST char *rhost;
	int retval = PAM_AUTH_ERR, debug;

	char recv_buffer[4096];
	char send_buffer[4096];
	AUTH_HDR *request = (AUTH_HDR *) send_buffer;
	AUTH_HDR *response = (AUTH_HDR *) recv_buffer;
	radius_conf_t config;

	(void)_pam_parse(pamh, argc, argv, &config);

	/*
	 * Get the IP address of the authentication server
	 * Then, open a socket, and bind it to a port
	 * Called early, so we can set debug flag
	 */
	retval = initialize(pamh, &config);
	PAM_FAIL_CHECK;

	debug = config.debug + cfg_debug;

	/* grab the user name */
	retval = pam_get_user(pamh, &user, NULL);
	PAM_FAIL_CHECK;

	/* check that they've entered something, and not too long, either */
	if ((user == NULL) || (strlen(user) > MAXPWNAM)) {
		retval = PAM_USER_UNKNOWN;
		PAM_FAIL_CHECK;
	}

	if (status == PW_STATUS_STOP && !__remove_mapfile(pamh, user, debug))
		retval = PAM_USER_UNKNOWN;
	PAM_FAIL_CHECK;

	/*
	 * If there's no client id specified, use the service type, to help
	 * keep track of which service is doing the authentication.
	 */
	if (!config.client_id) {
		retval = pam_get_item(pamh, PAM_SERVICE,
				      (CONST void **)&config.client_id);
		PAM_FAIL_CHECK;
	}

	/* build and initialize the RADIUS packet */
	request->code = PW_ACCOUNTING_REQUEST;
	get_random_vector(request->vector);
	request->id = request->vector[0];	/* this should be evenly distributed */

	build_radius_packet(request, user, NULL, &config);

	add_int_attribute(request, PW_ACCT_STATUS_TYPE, status);

	sprintf(recv_buffer, "%08d", (int)getpid());
	add_attribute(request, PW_ACCT_SESSION_ID, (unsigned char *)recv_buffer,
		      strlen(recv_buffer));

	add_int_attribute(request, PW_ACCT_AUTHENTIC, PW_AUTH_RADIUS);

	if (status == PW_STATUS_START) {
		time_t *session_time = malloc(sizeof(time_t));
		time(session_time);
		pam_set_data(pamh, "rad_session_time", (void *)session_time,
			     _int_free);
	} else {
		time_t *session_time;
		retval =
		    pam_get_data(pamh, "rad_session_time",
				 (CONST void **)&session_time);
		PAM_FAIL_CHECK;

		add_int_attribute(request, PW_ACCT_SESSION_TIME,
				  time(NULL) - *session_time);
	}

	/*
	 *      Tell the server which host the user is coming from.
	 *
	 *      Note that this is NOT the IP address of the machine running PAM!
	 *      It's the IP address of the client.
	 */
	retval = pam_get_item(pamh, PAM_RHOST, (CONST void **)&rhost);
	PAM_FAIL_CHECK;
	if (rhost) {
		add_attribute(request, PW_CALLING_STATION_ID,
			      (unsigned char *)rhost, strlen(rhost));
	}

	retval =
	    talk_radius(&config, request, response, NULL, NULL, 1, pamh, 1);
	PAM_FAIL_CHECK;

	/* oops! They don't have the right password.    Complain and die. */
	if (response->code != PW_ACCOUNTING_RESPONSE) {
		retval = PAM_PERM_DENIED;
		goto error;
	}

	retval = PAM_SUCCESS;

 error:
	return retval;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t * pamh, int flags, int argc,
				   CONST char **argv)
{
	return pam_private_session(pamh, flags, argc, argv, PW_STATUS_START);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t * pamh, int flags, int argc,
				    CONST char **argv)
{
	return pam_private_session(pamh, flags, argc, argv, PW_STATUS_STOP);
}

#undef PAM_FAIL_CHECK
#define PAM_FAIL_CHECK if (retval != PAM_SUCCESS) { goto error; }
#define MAX_PASSWD_TRIES 3

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t * pamh, int flags, int argc,
				CONST char **argv)
{
	CONST char *user;
	char *password = NULL;
	char *new_password = NULL;
	char *check_password = NULL;
	int ctrl;
	int retval = PAM_AUTHTOK_ERR;
	int attempts;
	char recv_buffer[4096];
	char send_buffer[4096];
	AUTH_HDR *request = (AUTH_HDR *) send_buffer;
	AUTH_HDR *response = (AUTH_HDR *) recv_buffer;
	radius_conf_t config;

	ctrl = _pam_parse(pamh, argc, argv, &config);

	/*
	 * Get the IP address of the authentication server
	 * Then, open a socket, and bind it to a port
	 */
	retval = initialize(pamh, &config);
	PAM_FAIL_CHECK;

	/* grab the user name */
	retval = pam_get_user(pamh, &user, NULL);
	PAM_FAIL_CHECK;

	/* check that they've entered something, and not too long, either */
	if ((user == NULL) || (strlen(user) > MAXPWNAM)) {
		return PAM_USER_UNKNOWN;
	}

	/*
	 * If there's no client id specified, use the service type, to help
	 * keep track of which service is doing the authentication.
	 */
	if (!config.client_id) {
		retval =
		    pam_get_item(pamh, PAM_SERVICE,
				 (CONST void **)&config.client_id);
		PAM_FAIL_CHECK;
	}

	/* grab the old password (if any) from the previous password layer */
	retval = pam_get_item(pamh, PAM_OLDAUTHTOK, (CONST void **)&password);
	PAM_FAIL_CHECK;
	if (password)
		password = strdup(password);

	/* grab the new password (if any) from the previous password layer */
	retval = pam_get_item(pamh, PAM_AUTHTOK, (CONST void **)&new_password);
	PAM_FAIL_CHECK;
	if (new_password)
		new_password = strdup(new_password);

	/* preliminary password change checks. */
	if (flags & PAM_PRELIM_CHECK) {
		if (!password) {	/* no previous password: ask for one */
			retval = rad_converse(pamh, PAM_PROMPT_ECHO_OFF,
					      config.prompt, &password);
			PAM_FAIL_CHECK;
		}

		/*
		 * We now check the password to see if it's the right one.
		 * If it isn't, we let the user try again.
		 * Note that RADIUS doesn't have any concept of 'root'. The only way
		 * that root can change someone's password is to log into the RADIUS
		 * server, and and change it there.
		 */

		/* build and initialize the access request RADIUS packet */
		request->code = PW_AUTHENTICATION_REQUEST;
		get_random_vector(request->vector);
		request->id = request->vector[0];	/* this should be evenly distributed */

		build_radius_packet(request, user, password, &config);
		add_int_attribute(request, PW_USER_SERVICE_TYPE,
				  PW_AUTHENTICATE_ONLY);

		retval =
		    talk_radius(&config, request, response, password, NULL, 1,
				pamh, 0);
		PAM_FAIL_CHECK;

		/* oops! They don't have the right password.    Complain and die. */
		if (response->code != PW_AUTHENTICATION_ACK) {
			_pam_forget(password);
			retval = PAM_PERM_DENIED;
			goto error;
		}

		/*
		 * We're now sure it's the right user.
		 * Ask for their new password, if appropriate
		 */

		if (!new_password) {	/* not found yet: ask for it */
			int new_attempts;
			attempts = 0;

			/* loop, trying to get matching new passwords */
			while (attempts++ < 3) {

				/* loop, trying to get a new password */
				new_attempts = 0;
				while (new_attempts++ < 3) {
					retval =
					    rad_converse(pamh,
							 PAM_PROMPT_ECHO_OFF,
							 "New password: ",
							 &new_password);
					PAM_FAIL_CHECK;

					/* the old password may be short.       Check it, first. */
					if (strcmp(password, new_password) == 0) {	/* are they the same? */
						rad_converse(pamh,
							     PAM_ERROR_MSG,
							     "You must choose a new password.",
							     NULL);
						_pam_forget(new_password);
						continue;
					} else if (strlen(new_password) < 6) {
						rad_converse(pamh,
							     PAM_ERROR_MSG,
							     "it's WAY too short",
							     NULL);
						_pam_forget(new_password);
						continue;
					}

					/* insert crypt password checking here */

					break;	/* the new password is OK */
				}

				if (new_attempts >= 3) {	/* too many new password attempts: die */
					retval = PAM_AUTHTOK_ERR;
					goto error;
				}

				/* make sure of the password by asking for verification */
				retval = rad_converse(pamh, PAM_PROMPT_ECHO_OFF,
						      "New password (again): ",
						      &check_password);
				PAM_FAIL_CHECK;

				retval = strcmp(new_password, check_password);
				_pam_forget(check_password);

				/* if they don't match, don't pass them to the next module */
				if (retval != 0) {
					_pam_forget(new_password);
					rad_converse(pamh, PAM_ERROR_MSG,
						     "You must enter the same password twice.",
						     NULL);
					retval = PAM_AUTHTOK_ERR;
					goto error;	/* ??? maybe this should be a 'continue' ??? */
				}

				break;	/* everything's fine */
			}	/* loop, trying to get matching new passwords */

			if (attempts >= 3) {	/* too many new password attempts: die */
				retval = PAM_AUTHTOK_ERR;
				goto error;
			}
		}

		/* now we have a new password which passes all of our tests */
		/*
		 * Solaris 2.6 calls pam_sm_chauthtok only ONCE, with PAM_PRELIM_CHECK
		 * set.
		 */
#ifndef sun
		/* If told to update the authentication token, do so. */
	} else if (flags & PAM_UPDATE_AUTHTOK) {
#endif

		if (!password || !new_password) {	/* ensure we've got passwords */
			retval = PAM_AUTHTOK_ERR;
			goto error;
		}

		/* build and initialize the password change request RADIUS packet */
		request->code = PW_PASSWORD_REQUEST;
		get_random_vector(request->vector);
		/* this should be evenly distributed */
		request->id = request->vector[0];

		/* the secret here can not be known to the user,
		 * so it's the new password */
		_pam_forget(config.server->secret);
		/* freed in cleanup_conf() */
		config.server->secret = strdup(password);

		build_radius_packet(request, user, new_password, &config);
		add_password(request, PW_OLD_PASSWORD, password, password);

		retval = talk_radius(&config, request, response, new_password,
				     password, 1, pamh, 0);
		PAM_FAIL_CHECK;

		/* Whew! Done password changing, check for password acknowledge */
		if (response->code != PW_PASSWORD_ACK) {
			retval = PAM_AUTHTOK_ERR;
			goto error;
		}
	}

	/*
	 * Send the passwords to the next stage if preliminary checks fail,
	 * or if the password change request fails.
	 */
	if ((flags & PAM_PRELIM_CHECK) || (retval != PAM_SUCCESS)) {
 error:

		/* If there was a password pass it to the next layer */
		if (password && *password) {
			pam_set_item(pamh, PAM_OLDAUTHTOK, password);
		}

		if (new_password && *new_password) {
			pam_set_item(pamh, PAM_AUTHTOK, new_password);
		}
	}

	if (ctrl & PAM_DEBUG_ARG) {
		_pam_log(pamh, LOG_DEBUG, "password change %s",
			 retval == PAM_SUCCESS ? "succeeded" : "failed");
	}

	_pam_forget(password);
	_pam_forget(new_password);
	return retval;
}

/*
 *	Do nothing for account management. This is apparently needed by
 *	some programs.
 */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t * pamh, int flags, int argc,
				CONST char **argv)
{
	int retval;
	retval = PAM_SUCCESS;
	return retval;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_radius_modstruct = {
	"pam_radius_auth",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok,
};
#endif
