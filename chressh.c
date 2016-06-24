/* chressh.c
 *   restricted (non-)login shell to allow (non-shell) users to run commands --
 *   such as scp, sftp-server, rsync, and unison -- over a secure channel.
 *   chroot()s a user to homedir, or, optionally, to shared directory above it,
 *     before starting target command.
 *   (further information in Notes section located at the bottom of this file)
 *
 *
 * Copyright (c) 2003  Glue Logic LLC  All rights reserved  code()gluelogic.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 *   Free Software Foundation, Inc.
 *   59 Temple Place - Suite 330
 *   Boston, MA 02111-1307, USA
 *
 * Full text of the GNU General Public License may be found at:
 *   http://www.gnu.org/copyleft/gpl.html
 */


/*
 * CONFIGURATION BEGIN
 */

/* user's shell in passwd database MUST match this hard-coded path
 * (this is for the same reason that the system allows only root to chroot())
 */
#ifndef CHROOTING_SHELL
#define CHROOTING_SHELL "/usr/local/sbin/chressh"
#endif

/* chrooted path (relative to starting dir (homedir)) to directory containing
 * allowed (and secured) programs.  It must end in '/'.  (use "./" for root)
 */
#ifndef CHROOTED_CMD_DIR
#define CHROOTED_CMD_DIR ".chressh/bin/"
#endif

/* chroot dir instead of homedir when user is a member of multiple groups
 * (user's homedir must be beneath this directory or else this is not used)
 * (This program will chroot to homedir if user is member of only one group)
 * (Include the trailing slash for a full directory path segment prefix match.
 *  While the GROUP_CHROOT_DIR then will not match if homedir is identical to
 *  GROUP_CHROOT_DIR (without a trailing slash), the results will be the same:
 *  chroot()ing to the homedir (which is the same dir as GROUP_CHROOT_DIR))
 */
#ifndef GROUP_CHROOT_DIR
#define GROUP_CHROOT_DIR "/nonexistent/"  /* set to bogus dir to disable */
/* #define GROUP_CHROOT_DIR "/pub/" */
#endif

/* umask default */
#ifndef UMASK
#define UMASK 0022
/* #define UMASK 0002 */	/* useful in environments based around groups */
#endif

/* path to 'passwd' (or equivalent) command */
#ifndef PASSWD_PROGRAM
#define PASSWD_PROGRAM "/usr/bin/passwd"
#endif
/* #undef PASSWD_PROGRAM */ /* undefine PASSWD_PROGRAM to disable */

/* system priority and resource limits */
#define CHRESSH_PRIO  15 /* lower priority to 15 */
#define CHRESSH_STACK 16777216L /* arbitrarily 16MiB stack size */
#define CHRESSH_DATA  33554432L /* arbitrarily 32MiB memory size */

/* define to a value of 1 as appropriate if system has <wordexp.h> or <glob.h>
 * The reason this is not autoconf'ed is that on some systems, wordexp() forks
 * a subshell to do its expansion, and that will fail in our restricted chroot.
 * On those systems, leave #define HAVE_WORDEXP_H 0.
 */
#define HAVE_WORDEXP_H 1
#define HAVE_GLOB_H    0

/*
 * CONFIGURATION END
 */


#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
extern char **environ;
#if HAVE_WORDEXP_H
#include <wordexp.h>
#endif
#if HAVE_GLOB_H
#include <glob.h>
#endif


/* minimum number of processes each target requires to run */
#define NPROC_RSYNC 3
#define NPROC_SCP 1
#define NPROC_SFTP_SERVER 1
#define NPROC_UNISON 1


/* informative message to return if a system call failed */
#define SYSTEM_ERROR_MESG \
  "\n\tA system error occurred while attempting to execute your command.\n" \
  "\n\tPlease contact the systems administrator for further assistance.\n\n"
/* informative message to return if login attempt is made */
#define NOLOGIN_MESG \
  "\n\tYou do not have interactive login access to this machine.\n" \
  "\n\tPlease contact the systems administrator for further assistance.\n\n"
/* informative message to return if a this program is not user's shell */
#define SHELL_MISMATCH_MESG \
  "\n\tYou are not permitted to call this program.\n" \
  "\n\tPlease contact the systems administrator for further assistance.\n\n"
/* informative message to return if run as root */
#define ROOT_RUID_MESG \
  "\n\treal UID (target UID) of root is not allowed\n\n"
/* informative message to return if invalid args passed */
#define BAD_ARGS_MESG \
  "\n\tInvalid arguments; command not allowed.\n" \
  "\n\tPlease contact the systems administrator for further assistance.\n\n"

static void __attribute__((noreturn))
fatal(const int argc,
      /*@null@*/ const struct passwd * const pw,
      /*@null@*/ const char * const chroot_dir)
/*@globals errno@*/
/*@modifies errno@*/
{
    const int s_errno = errno;
    const char *mesg  = NULL;

    openlog("chressh", LOG_PID, LOG_AUTHPRIV);

    if (s_errno) {
	syslog (LOG_NOTICE, "system error occurred for uid %lu (%s) (%s)",
		(unsigned long) (pw ? pw->pw_uid : getuid()),
		pw ? pw->pw_name : "", strerror(s_errno));
	mesg = SYSTEM_ERROR_MESG;
    }
    else if (NULL == pw) {
	syslog (LOG_NOTICE, "login attempted by invalid uid %lu",
		(unsigned long) getuid());
	mesg = NOLOGIN_MESG;
    }
    else if (0 == pw->pw_uid) {
	syslog (LOG_NOTICE, "real UID (target UID) of root is not allowed");
	mesg = ROOT_RUID_MESG;
    }
    else if (0 != memcmp(pw->pw_shell,CHROOTING_SHELL,sizeof(CHROOTING_SHELL))){
	syslog (LOG_NOTICE, "shell mismatch by uid %lu (%s)",
		(unsigned long) pw->pw_uid, pw->pw_name);
	mesg = SHELL_MISMATCH_MESG;
    }
    else if (NULL != chroot_dir) {
	syslog (LOG_NOTICE, "unsafe ownership or permissions on chroot (%s)"
		"for uid %lu (%s)", chroot_dir, (unsigned long) pw->pw_uid,
		pw->pw_name);
	mesg = SYSTEM_ERROR_MESG;
    }
    else if (1 == argc) {
	syslog (LOG_NOTICE, "login attempted by uid %lu (%s)",
		(unsigned long) pw->pw_uid, pw->pw_name);
	mesg = NOLOGIN_MESG;
    }
    else {
	syslog (LOG_NOTICE, "bad args passed by uid %lu (%s)",
		(unsigned long) pw->pw_uid, pw->pw_name);
	mesg = BAD_ARGS_MESG;
    }

    (void) sleep(3);
    if (NULL != mesg) {
	(void) write(STDERR_FILENO, mesg, strlen(mesg));
    }

    exit(s_errno ? s_errno : 1);
}


/* Perl script used to generate hash_long_args[] from lists below

#!/usr/bin/perl -Tw
use constant HASH_SIZE => 32;
my @hash;
my $val;
$hash[$_] = [] foreach (0..HASH_SIZE);
foreach my $arg (<>) {
    chomp $arg;
    $val = 0;
    map { $val = ($val + ord($_)) % HASH_SIZE } split //,$arg;
    push @{$hash[$val]},$arg;
}
my $list = "    {\n";
foreach (@hash) {
    $list .=
      scalar @$_
	? ('      { "' . join('", "', @$_) . "\", NULL },\n")
	: "      { NULL },\n";
}
substr($list,-2,2,"\n    }\n");
print $list;

*/

/* rsync
 * Disallow "--daemon" "--no-detach" "--address" "--port" "--config"
 * "--devices" "--owner" "--rsh=COMMAND" "--rsync-path=PATH" along with "-e"
 *
 * Allowed rsync long args with required param
 *
suffix
block-size
max-delete
timeout
modify-window
temp-dir
compare-dest
link-dest
exclude
exclude-from
include
include-from
files-from
log-format
password-file
bwlimit
write-batch
read-batch
 *
 * Allowed rsync long args with no param
 *
server
sender
verbose
quiet
checksum
archive
recurse
relative
no-relative
no-implied-dirs
backup
backup-dir
update
links
copy-links
copy-unsafe-links
safe-links
hard-links
perms
owner
group
devices
times
sparse
dry-run
whole-file
no-whole-file
one-file-system
existing
ignore-existing
delete
delete-excluded
delete-after
ignore-errors
partial
force
numeric-ids
ignore-times
size-only
compress
cvs-exclude
from0
version
blocking-io
no-blocking-io
stats
progress
help
 */

/* unison
 * Disallow "-socket" "-server" "-servercmd" "-rshcmd" "-rshargs" "-editor"
 * "-diff" "-merge" "-merge2" "-owner" "-sshcmd" "-sshversion"
 *
 * Allowed unison "long" args with required param
 *
addprefsto
backup
debug
doc
fastcheck
follow
force
height
ignore
ignorenot
key
label
logfile
maxbackups
path
perms
prefer
root
rootalias
sortfirst
sortlast
statusdepth
ui
 *
 * Allowed unison "long" args with no param
 *
addversionno
auto
backups
batch
contactquietly
dumbtty
group
help
ignorecase
killserver
log
numericids
silent
sortbysize
sortnewfirst
terse
testserver
times
version
xferbycopying
 */

/* hard-code allowed args and reject others (default deny, not default allow) */

#define HASH_SIZE (1<<5)  /* 1<<5 == 32; must be a power of 2 */
enum { HASH_RSYNC_A=0, HASH_RSYNC_B=1, HASH_UNISON_A=2, HASH_UNISON_B=3 };

static const char *hash_long_args[4][HASH_SIZE+1][8] =
  {
    { /* rsync (with param) */
      { "password-file", NULL },
      { NULL },
      { "temp-dir", NULL },
      { NULL },
      { "compare-dest", "include", NULL },
      { "include-from", NULL },
      { "max-delete", NULL },
      { "timeout", NULL },
      { NULL },
      { NULL },
      { "exclude", NULL },
      { "link-dest", "exclude-from", "read-batch", NULL },
      { NULL },
      { "modify-window", NULL },
      { NULL },
      { NULL },
      { NULL },
      { NULL },
      { NULL },
      { "block-size", NULL },
      { "files-from", NULL },
      { "suffix", NULL },
      { NULL },
      { NULL },
      { "log-format", "bwlimit", NULL },
      { NULL },
      { "write-batch", NULL },
      { NULL },
      { NULL },
      { NULL },
      { NULL },
      { NULL },
      { NULL }
    },
    { /* rsync (no param) */
      { "numeric-ids", NULL },
      { "sender", "links", "one-file-system", NULL },
      { "archive", "backup-dir", "times", NULL },
      { "update", "devices", "cvs-exclude", NULL },
      { "from0", NULL },
      { NULL },
      { "no-relative", "version", NULL },
      { "perms", NULL },
      { "quiet", NULL },
      { "copy-links", "help", NULL },
      { "size-only", NULL },
      { "owner", "existing", NULL },
      { "whole-file", "compress", NULL },
      { "no-implied-dirs", "safe-links", "hard-links", "group", "partial",NULL},
      { "sparse", "delete-excluded", "ignore-errors", "blocking-io", NULL },
      { "force", "stats", NULL },
      { NULL },
      { "dry-run", NULL },
      { "delete-after", NULL },
      { "checksum", "delete", "ignore-times", NULL },
      { NULL },
      { "progress", NULL },
      { "verbose", "backup", "no-whole-file", NULL },
      { "server", NULL },
      { "copy-unsafe-links", "no-blocking-io", NULL },
      { "recurse", NULL },
      { NULL },
      { NULL },
      { "relative", "ignore-existing", NULL },
      { NULL },
      { NULL },
      { NULL },
      { NULL }
    },
    { /* unison (with param) */
      { "label", NULL },
      { NULL },
      { "logfile", NULL },
      { NULL },
      { "ignore", "prefer", "root", NULL },
      { NULL },
      { NULL },
      { "debug", "perms", NULL },
      { NULL },
      { "key", NULL },
      { NULL },
      { NULL },
      { "addprefsto", "fastcheck", NULL },
      { "path", NULL },
      { "rootalias", NULL },
      { "force", "maxbackups", NULL },
      { "sortfirst", NULL },
      { NULL },
      { NULL },
      { "follow", NULL },
      { NULL },
      { "ignorenot", NULL },
      { "backup", "doc", NULL },
      { NULL },
      { NULL },
      { "height", "statusdepth", NULL },
      { NULL },
      { NULL },
      { "sortlast", NULL },
      { NULL },
      { "ui", NULL },
      { NULL },
      { NULL }
    },
    { /* unison (no param) */
      { "ignorecase", NULL },
      { NULL },
      { "batch", "log", "times", NULL },
      { "killserver", "terse", NULL },
      { NULL },
      { NULL },
      { "version", NULL },
      { NULL },
      { NULL },
      { "backups", "dumbtty", "help", "xferbycopying", NULL },
      { NULL },
      { NULL },
      { "addversionno", NULL },
      { "group", NULL },
      { NULL },
      { "silent", NULL },
      { NULL },
      { NULL },
      { NULL },
      { "numericids", NULL },
      { NULL },
      { NULL },
      { NULL },
      { "testserver", NULL },
      { NULL },
      { "auto", "contactquietly", NULL },
      { "sortnewfirst", NULL },
      { NULL },
      { NULL },
      { NULL },
      { "sortbysize", NULL },
      { NULL },
      { NULL }
    }
  };


static int
hash_lookup_long_arg(const int hash_e, const char * const str)
/*@globals hash_rsync, hash_unison_a, hash_unison_b@*/
/*@modifies nothing@*/
{
    const char * const *h;
    const char c = *str;
    unsigned char * const s = (unsigned char *) str;
    unsigned char *p;
    const size_t len = (NULL == (p=strchr(s,'='))) ? strlen(s) : (size_t)(p-s);
    size_t i;
    int val = 0;
    for (i = 0; i < len; i++)
	val = (val + s[i]) & (HASH_SIZE-1);
    h = hash_long_args[hash_e][val];
    for (i = 0; NULL != h[i] && (c != *h[i] || 0 != memcmp(h[i],str,len)); i++)
	;
    return (NULL != h[i]);
}


static int
filter_args_rsync(char ** const argv)
/*@modifies nothing@*/
{
    char *s;
    unsigned int require_param = 0;
    size_t i = 0;
    size_t j = 0;

    while (NULL != (s = argv[i++])) {
	if (1 == require_param || '-' != s[0]) {
	    require_param = 0;
	}
	else if ('-' != s[1]) {
	    for (j = 1; s[j] != '\0'; j++) {  /* (implicity allows "-" arg) */
		/* "-e" disallowed */
		if ('B' == s[j] || 'T' == s[1]) {
		    require_param = 1;
		    if ('\0' != s[j+1]) {
			return -1; /* bad combination of args */
		    }
		}
		else if (NULL == strchr("046CDHILPRSWabcghlnopqrtuvxz", s[j])) {
		    /* long args beginning with single '-' are rejected
		     * here even though they are supported by popt,
		     * which is employed by rsync to parse its args
		     */
		    return -1; /* disallowed or unknown */
		}
	    }
	}
	else if ('\0' == s[2]) {  /* "--" indicates end of args */
	    return 0;
	}
	else if (0 != hash_lookup_long_arg(HASH_RSYNC_A, s+2)) {
	    if (NULL == strchr(s+2, '=')) {
		require_param = 1;
	    }
	}
	else if (0 == hash_lookup_long_arg(HASH_RSYNC_B, s+2)) {
	    return -1; /* disallowed or unknown */
	}
    }
    return (0 == require_param) ? 0 : -1;
}


static int
filter_args_unison(char ** const argv)
/*@modifies nothing@*/
{
    char *s;
    unsigned int require_param = 0;
    size_t i = 0;
    /* Check the number of non-options because unison profiles are
     * not allowed (they can be used to execute arbitrary programs).
     * Usage: unison [options]                          (1 non-option)
     *     or unison root1 root2 [options]              (3 non-options)
     *     or unison profilename [options]              (disallowed)
     * (also unison profilename root1 root2 [options])  (disallowed)
     * (MUST TEST HOW UNISON HANDLES "-" AS PROFILENAME OR ROOT)
     * (and if it handles "--")
     */
    while (NULL != argv[i] && ('-' != argv[i][0] || '\0' == argv[i][1])) {
	i++;
    }
    if (1 != i && 3 != i) {
	return -1; /* unison profiles disallowed */
    }
    while (NULL != (s = argv[i++])) {
	if (1 == require_param) {
	    require_param = 0;
	}
	else if ('-' != s[0]) {
	    return -1; /* disallowed or unknown */
	}
	else if (0 != hash_lookup_long_arg(HASH_UNISON_A, s+1)) {
	    require_param = 1;
	}
	else if (0 == hash_lookup_long_arg(HASH_UNISON_B, s+1)) {
	    return -1; /* disallowed or unknown */
	}
    }
    return (0 == require_param) ? 0 : -1;
}


#if !HAVE_WORDEXP_H

/* This routine is quite simpleton.  It performs very loose syntax checking,
 * and treats newlines as spaces.  It supports only brain-dead limited quoting
 * (no quoting within words), and provides absolutely no support for escaping.
 */
/*@null@*/
static char **
simpleton_wordsplit(char *args)
/*@globals errno@*/
/*@modifies errno@*/
{
    int i = -1;
    const int max = 31; /*(arbitrarily limit to command + 30 args + NULL)*/
    char ** const argv = malloc((max + 1) * sizeof(char *));
    if (NULL == argv) {
	return NULL;
    }

    while ('\0' != *args && i < max) {
	switch (*args) {
	  case ' ' :
	  case '\t':
	  case '\n':*args++;
		    continue;
	  case '"': argv[++i] = ++args;
		    args = strchr(args, '"');
		    break;
	  case '\'':argv[++i] = ++args;
		    args = strchr(args, '\'');
		    break;
	  default:  argv[++i] = args++;
		    args += strcspn(args, " \t\n");
		    if ('\0' != *args) {
			*args++ = '\0';
		    }
		    continue;
	}

	/* (limited to supporting quotes around entire word) */
	if (NULL != args) {
	    *args++ = '\0';
	}
	else {
	    return (free(argv), NULL);
	}
    }

    return (i < max || '\0'==*args) ? (argv[i+1]=NULL,argv) : (free(argv),NULL);
}

#endif /* !HAVE_WORDEXP_H */


#if !HAVE_WORDEXP_H && HAVE_GLOB_H
#include <stdio.h>

static int
glob_errfunc(const char *epath, int eerrno)
{
    (void) fprintf(stderr, "\nglob() error (%s) for path:\n%s\n",
		   strerror(eerrno), epath);
    return 1;  /* (anything non-zero) */
}

#endif /* !HAVE_WORDEXP_H && HAVE_GLOB_H */


/*@null@*/
static char **
shell_parse(char * const args)
/*@globals errno@*/
/*@modifies errno@*/
{
    char **argv;

  #if HAVE_WORDEXP_H || HAVE_GLOB_H
    int rv;
    struct rlimit limits;
    rlim_t soft_limit;
    #ifdef RLIMIT_AS
    rv = getrlimit(RLIMIT_AS, &limits);
    #else
    rv = getrlimit(RLIMIT_DATA, &limits);
    #endif
    if (0 == rv) {
	soft_limit = limits.rlim_cur;
	if (soft_limit > (ARG_MAX<<5)) {
	    limits.rlim_cur = ARG_MAX<<5;
	  #ifdef RLIMIT_AS
	    rv = setrlimit(RLIMIT_AS, &limits);
	  #else
	    rv = setrlimit(RLIMIT_DATA, &limits);
	  #endif
	}
    }
    if (0 != rv) {
	return NULL;
    }
  #endif /* HAVE_WORDEXP_H || HAVE_GLOB_H */


  #if HAVE_WORDEXP_H

    /* (wordexp() implementations that execute a subshell will probably fail) */
    /* (tilde expansion will probably fail because chroot; prefer ~/ or $HOME)*/
    /* (we.we_wordv contents malloc()ed even though 'we' is from stack) */
    {
	wordexp_t we;
	switch (wordexp(args, &we, WRDE_NOCMD|WRDE_UNDEF)) {
	  case 0:            argv = we.we_wordv; break;
	  case WRDE_NOSPACE: errno = ENOMEM; /*@fallthrough@*/
	  default:           wordfree(&we); return NULL;
	}
    }

  #else /* !HAVE_WORDEXP_H */

    argv = simpleton_wordsplit(args);

    #if HAVE_GLOB_H
    if (NULL != argv) {
	size_t i = 0;
	glob_t gl;

	rv = GLOB_ABORTED;
	gl.gl_pathv = NULL;
	if (NULL != argv[0]) {
	    rv = glob(argv[0], GLOB_ERR|GLOB_NOSORT|GLOB_NOCHECK,
		      glob_errfunc, &gl);
	}
	while ((0 == rv || GLOB_NOMATCH == rv) && NULL != argv[++i]) {
	    rv = glob(argv[i], GLOB_ERR|GLOB_NOSORT|GLOB_NOCHECK|GLOB_APPEND,
		      glob_errfunc, &gl);
	}

	/* (gl.gl_pathv contents malloc()ed even though 'gl' is from stack) */
	switch (rv) {
	  case 0:
	  case GLOB_NOMATCH:
	    free(argv);
	    argv = gl.gl_pathv;
	    break;
	  case GLOB_NOSPACE:
	    errno = ENOMEM; /*@fallthrough@*/
	  case GLOB_ABORTED:
	  default:
	    if (NULL != argv[i]) {
		(void)
		fprintf(stderr, "glob() error at pattern:\n%s\n\n", argv[i]);
	    }
	    globfree(&gl);
	    free(argv);
	    argv = NULL;
	    exit(1);
	}
    }
    #endif /* HAVE_GLOB_H */

  #endif /* !HAVE_WORDEXP_H */


  #if HAVE_WORDEXP_H || HAVE_GLOB_H
    if (soft_limit > limits.rlim_cur) {
	limits.rlim_cur = soft_limit;
      #ifdef RLIMIT_AS
	(void) setrlimit(RLIMIT_AS, &limits);
      #else
	(void) setrlimit(RLIMIT_DATA, &limits);
      #endif
    }
  #endif /* HAVE_WORDEXP_H || HAVE_GLOB_H */

    return argv;
}


static int
set_limits(const rlim_t nproc)
/*@globals errno@*/
/*@modifies errno@*/
{
    int rv;
    struct rlimit limits;

    errno = 0;
    rv = getpriority(PRIO_PROCESS, 0);
    if (rv < 15 && (rv != -1 || 0 == errno)) {
	rv = setpriority(PRIO_PROCESS, 0, CHRESSH_PRIO);
    }
    if (0 != rv) {
	return rv;
    }

  #ifdef RLIMIT_AS
    rv = getrlimit(RLIMIT_AS, &limits);
  #else
    rv = getrlimit(RLIMIT_DATA, &limits);
  #endif
    if (0 == rv) {
	if (limits.rlim_max > CHRESSH_DATA) {
	    limits.rlim_cur = CHRESSH_DATA;
	    limits.rlim_max = CHRESSH_DATA;
	  #ifdef RLIMIT_AS
	    rv = setrlimit(RLIMIT_AS, &limits);
	  #else
	    rv = setrlimit(RLIMIT_DATA, &limits);
	  #endif
	}
    }
    if (0 != rv) {
	return rv;
    }
    rv = getrlimit(RLIMIT_STACK, &limits);
    if (0 == rv) {
	if (limits.rlim_max > CHRESSH_STACK) {
	    limits.rlim_cur = CHRESSH_STACK;
	    limits.rlim_max = CHRESSH_STACK;
	    rv = setrlimit(RLIMIT_STACK, &limits);
	}
    }
    if (0 != rv) {
	return rv;
    }
    limits.rlim_cur = nproc;
    limits.rlim_max = nproc;
    return setrlimit(RLIMIT_NPROC, &limits);  /* limit num processes allowed */
}


/* preserve only minimalist environment for sftp, rsync, and unison to work
 * Note that it is expected that environment is created by system on login
 * and therefore that the environment is sane, e.g. no duplicated variables
 * or other mischief.
 */
static char **
env_clean(char **env, struct passwd * const pw,
	  /*@null@*/ const char * const home)
/*@globals errno@*/
/*@modifies env, errno@*/
{
    unsigned int i;
    unsigned int j;
    char **path = NULL;
    size_t home_len = 0;
    unsigned int need_home = 0;
    unsigned int need_posixly_correct = 1;

    if (NULL != home) {
	home_len = strlen(home);
	need_home = 1;
    }

    for (i = j = 0; env[j] != NULL; j++) {
	switch (*env[j]) {
	  case 'C': if (0 == memcmp(env[j], "CVSIGNORE=", 10)) 
			break;
		    continue;
	  case 'H': if (0 == memcmp(env[j], "HOME=", 5)) {
			if (NULL != home) {
			    if (strlen(env[j]+5) >= home_len) {
				memcpy(env[j]+5, home, home_len+1);
				need_home = 0;
				break;
			    }
			}
			else {
			    break;
			}
		    }
		    continue;
	  case 'L': if (0 == memcmp(env[j], "LANG=", 5)
			|| 0 == memcmp(env[j], "LANGUAGE=", 9)
			|| 0 == memcmp(env[j], "LC_", 3))     /*(prefix match)*/
			break;
		    else if (0 == memcmp(env[j], "LOGNAME=", 8))
			break;  /* (or could force pw->pw_name) */
		    continue;
	  case 'P': if (0 == memcmp(env[j], "PATH=", 5)) {
			path = &env[i];
			break;
		    }
		    else if (0 == memcmp(env[j], "POSIX", 5)){/*(prefix match)*/
			if (0 == memcmp(env[j]+5, "LY_CORRECT=", 11)) {
			    if ('\0' != env[j][16]) {
				env[j][16] = '1';
				env[j][17] = '\0';
				need_posixly_correct = 0;
				break;
			    }
			}
			else {
			    break;
			}
		    }
		    continue;
	  case 'R': if (0 == memcmp(env[j], "RSYNC_", 6)      /*(prefix match)*/
			&& 0 != memcmp(env[j]+6, "RSH", 4))   /*(no RSYNC_RSH)*/
			break;
		    continue;
	  case 'S': if (0 == memcmp(env[j], "SHELL=", 6))
			break;  /* (or could force pw->pw_shell) */
		    else if (0 == memcmp(env[j], "SSH", 3))   /*(prefix match)*/
			break;
		    continue;
	  case 'T': if (0 == memcmp(env[j], "TZ=", 3)) 
			break;
		    continue;
	  case 'U': if (0 == memcmp(env[j], "UNISON", 6)      /*(prefix match)*/
			&& '=' != env[j][6]) /* disallow "UNISON=..." */
			break; /* allow UNISONLOCALHOSTNAME, UNISONBACKUPDIR */
		    else if (0 == memcmp(env[j], "USER=", 5))
			break;  /* (or could force pw->pw_name) */
		    continue;
	  default : continue;
	}
	env[i++] = env[j];
    }

    if ((i + (NULL!=home&&NULL==path) + need_home + need_posixly_correct) > j) {
	char ** const env_new = malloc((i+4)*sizeof(char *));
	if (NULL == env_new) {
	    fatal(0, pw, NULL);
	}
	env = memcpy(env_new, env, i*sizeof(char *));
    }

    if (NULL != home) {
	if (NULL == path) {
	    path = env+(i++);
	}
	*path = malloc(5 + home_len + 1 + sizeof(CHROOTED_CMD_DIR));
	if (NULL == *path) {
	    fatal(0, pw, NULL);
	}
	memcpy(*path, "PATH=", 5);
	memcpy((*path)+5, home, home_len);
	(*path)[5 + home_len] = '/';
	memcpy((*path)+5+home_len+1,CHROOTED_CMD_DIR,sizeof(CHROOTED_CMD_DIR));

	if (need_home) {
	    char * const home_env = malloc(5 + home_len + 1);
	    if (NULL == *path) {
		fatal(0, pw, NULL);
	    }
	    memcpy(home_env, "HOME=", 5);
	    memcpy(home_env+5, home, home_len + 1);
	    env[i++] = home_env;
	}
    }

    if (need_posixly_correct) {
	/* insert POSIXLY_CORRECT=1 so that there is a better chance that
	 * programs using getopt_long() will parse args similar to how the
	 * filter_args_*() routines do in this program
	 */
	static char posixly_correct[] = "POSIXLY_CORRECT=1";
	env[i++] = posixly_correct;
    }

    env[i] = NULL;

    return env;
}


int
main(const int argc, char * const argv[])
/*@globals environ, errno@*/
/*@modifies environ, errno@*/
{
    struct passwd *pw;
    char **target_env = environ;
    static char *empty_env[] = { NULL };
    environ = empty_env;
    (void) umask(~(mode_t)0);  /* (no file perms, if signalled to dump core)*/

    /* check that calling UID exists, is not root, and shell matches */
    if (NULL != (pw = getpwuid(getuid()))
	&& 0 != pw->pw_uid
	&& 0 == memcmp(pw->pw_shell,CHROOTING_SHELL,sizeof(CHROOTING_SHELL)) ) {

	/* require commands of the form: "sh" "-c" "command args args args" */
	if (3 == argc && 0 == memcmp(argv[1], "-c", 3)) {
	    const char *chroot_dir = (const char *)pw->pw_dir;
	    const char *home = "/";
	    struct stat st;
	    if (0 == memcmp(pw->pw_dir, GROUP_CHROOT_DIR,
			    sizeof(GROUP_CHROOT_DIR)-1)
		&& getgroups(0, (gid_t *)NULL) > 1) {
		chroot_dir = GROUP_CHROOT_DIR;
		home = (const char *)pw->pw_dir+(sizeof(GROUP_CHROOT_DIR)-2);
		if (*home != '/' && *++home != '/') {
		    home = "/";
		}
	    }
	    if (!(   0 == stat(chroot_dir, &st)
		  && pw->pw_uid != st.st_uid  /* (not caller; typically root) */
		  && 0 == (st.st_mode & (S_IWGRP|S_IWOTH)))) {
		fatal(argc, pw, chroot_dir);
	    }
	    openlog("chressh", LOG_NDELAY|LOG_PID, LOG_AUTHPRIV);
	    if (/*@-superuser@*/
		   0 == chroot(chroot_dir)
		/*@=superuser@*/
		&& 0 == setuid(getuid())
		&& 0 != setuid(0)
		&& 0 == chdir(home)) {

		char **target_argv;
		size_t len;
		errno = 0;  /* (reset errno after expected setuid(0) failure) */

		environ = target_env = env_clean(target_env, pw, home);
		target_argv = shell_parse(argv[2]);
		if (NULL == target_argv || NULL == target_argv[0]) {
		    fatal(argc, pw, NULL);
		}
		(void) umask((mode_t)UMASK);

		if (0 == strcmp(target_argv[0], "scp")) {
		    if (0 == set_limits(NPROC_SCP)) {
			(void) execve(CHROOTED_CMD_DIR "scp",
				      target_argv, target_env);
		    }
		}
		else if (0 == strcmp(target_argv[0], "rsync")) {
		    if (0 == filter_args_rsync(target_argv)
			&& 0 == set_limits(NPROC_RSYNC)) {
			(void) execve(CHROOTED_CMD_DIR "rsync",
				      target_argv, target_env);
		    }
		}
		else if (0 == strcmp(target_argv[0], "unison")) {
		    if (0 == filter_args_unison(target_argv)
			&& 0 == set_limits(NPROC_UNISON)) {
			(void) execve(CHROOTED_CMD_DIR "unison",
				      target_argv, target_env);
		    }
		}
		else {
		    if (  11 <= (len = strlen(target_argv[0]))
			&& 0 == memcmp(target_argv[0]+len-11, "sftp-server", 11)
			&& 0 == set_limits(NPROC_SFTP_SERVER)) {
			/*('chressh -c /usr/local/libexec/sftp-server')*/
			/*(only tests for "sftp-server" suffix, which is fine)*/
			/*(discard additional args to sftp-server, if present)*/
			char sftp_server[] = "sftp-server";
			char *target_argv_static[] = { sftp_server, NULL };
			(void) execve(CHROOTED_CMD_DIR "sftp-server",
				      target_argv_static, target_env);
		    }
		}


#if 0  /* which code do you think is clearer?  above or below? */

		switch ((len = strlen(target_argv[0]))) {
		  case  3:
		    if (0 == memcmp(target_argv[0], "scp", 3)
			&& 0 == set_limits(NPROC_SCP)) {
			(void) execve(CHROOTED_CMD_DIR "scp",
				      target_argv, target_env);
		    }
		    break;
		  case  5:
		    if (0 == memcmp(target_argv[0], "rsync", 5)
			&& 0 == filter_args_rsync(target_argv)
			&& 0 == set_limits(NPROC_RSYNC)) {
			(void) execve(CHROOTED_CMD_DIR "rsync",
				      target_argv, target_env);
		    }
		    break;
		  case  6:
		    if (0 == memcmp(target_argv[0], "unison", 6)
			&& 0 == filter_args_unison(target_argv)
			&& 0 == set_limits(NPROC_UNISON)) {
			(void) execve(CHROOTED_CMD_DIR "unison",
				      target_argv, target_env);
		    }
		    break;
		  default:
		    if (  11 <= len
			&& 0 == memcmp(target_argv[0]+len-11, "sftp-server", 11)
			&& 0 == set_limits(NPROC_SFTP_SERVER)) {
			/*('chressh -c /usr/local/libexec/sftp-server')*/
			/*(only tests for "sftp-server" suffix, which is fine)*/
			/*(discard additional args to sftp-server, if present)*/
			char sftp_server[] = "sftp-server";
			char *target_argv_static[] = { sftp_server, NULL };
			(void) execve(CHROOTED_CMD_DIR "sftp-server",
				      target_argv_static, target_env);
		    }
		    break;
		}
#endif


	    }
	}

      #ifdef PASSWD_PROGRAM
	/* If login attempt (argc == 1), use PASSWD_PROGRAM as 'shell'
	 * (*argv[0] == '-', too, for login shells on most (all?) systems)
	 * (privileges intentionally dropped even if passwd_program setuid)
	 */
	else if (1 == argc && 0 == setuid(getuid()) && 0 != setuid(0)) {
	    char passwd_program[] = PASSWD_PROGRAM;
	    char *target_argv[] = { passwd_program, NULL };
	    errno = 0;  /* (reset errno after expected setuid(0) failure) */
	    target_env = env_clean(target_env, pw, NULL);
	    (void) execve(PASSWD_PROGRAM, target_argv, target_env);
	}
      #endif

    }

    fatal(argc, pw, NULL);
    return 0; /*(UNREACHED)*/
}


/*
 * Thanks to alpha auditors:
 * Brian Fisk, Andrew Schwerin, and other netspace.org folks
 *
 * 2004.03.11  v0.02  clean environment
 * 2004.03.18  v0.03  exec() of passwd program upon shell login attempt
 *                    instead of erroring out
 * 2004.03.22  v0.04  scp, rsync, and unison support
 */
/*
 * Additional Resources:
 * ---------------------
 * sftpsh
 *   http://mail.incredimail.com/howto/openssh/addons/sftpsh.c
 *   http://mail.incredimail.com/howto/openssh/
 *   Jason A. Dour's sftpsh.c, found after this code was written, also aims at
 *   being a simple SFTP-only shell.  chressh borrows some error messages.
 * rssh
 *   http://sourceforge.net/projects/rssh/
 * scponly
 *   http://www.sublimation.org/scponly/
 *
 *
 * chressh produces no warnings when run through Splint with:
 *   splint +checks +unixstrictlib chressh.c
 * (has been run with +strict and warnings verified as innocuous)
 */
/*
 * Notes:
 * ------
 * The user with the chressh shell should not own his/her home directory and
 *   there should not be group or other write privileges to it.  Within the
 *   homedir, the user should not have write privileges to CHROOTED_CMD_DIR,
 *   which contains the target programs chressh permits to be run.  It is
 *   recommended that the user not own or have write permission to the ~/.ssh/ 
 *   directory, although the admin might create ~/.ssh/authorized_keys and
 *   allow write permission on that single file.  (must be owned by user since
 *   sshd will ignore it if group or other have write permissions)
 *   Among other things, restricting write access to the top level of the
 *   homedir ~/ and of ~/.ssh/ means that the user can not manipulate dotfiles
 *   potentially changing the restricted behavior of the CHROOTED_CMD_DIR
 *   programs.
 *   If possible, the homedir should be on a partition mounted with the
 *   nosuid option, or else, if possible, no setuid/setgid programs should be
 *   located on the partition (to which some rogue might manage to hard link).
 * If possible, a dedicated sshd should run with sshd_config settings
 *   PermitRootLogin no
 *   AllowTcpForwarding no
 *   PrintMotd no
 *   PrintLastLog no
 *   X11Forwarding no           (default)
 *   PermitUserEnvironment no   (default)
 * Might also want to set "MaxStartups"  ('man sshd_config')
 *   MaxStartups 10:30:60
 *
 * If sshd_config is configured with "PrintMotd yes" (the default) then
 *   users with chressh as their shell will be able to see the MOTD before
 *   being disconnected if they attempt to ssh to the server instead of sftp.
 *
 * It would be safer if user homes were on partition mounted noexec, but then
 *   chroot dir would have to be at a higher level, or CHROOTED_CMD_DIR under
 *   home would need to be on something like an NFS loopback mounted exec.
 *   Also, would conflict with CGI scripts if that is what was located here
 *   (unless CGI were explicitly invoked through interpreters located elsewhere)
 *
 * There are differences in command line expansion depending on whether
 *   wordexp(), glob(), or neither are available on the platform.
 *   wordexp() is best, but unusable on some platforms since it forks a shell
 *   and that will fail inside the chroot because there is no shell (or at least
 *   you should try not to have a shell in the chroot).  glob() is a somewhat
 *   functional substitute, except that if you pass a wildcard that does not
 *   expand to any real path, then it will be passed as an argument as-is, with
 *   the wildcards, instead of the expected substitution of nothingness.  glob()
 *   and systems without glob() and without wordexp() employ a very limited and
 *   brain-dead simple routine for word-splitting, so beware of that limitation.
 *
 * /etc/nologin
 *   Depending on your sshd_config and your PAM configuration (other other
 *   login mechanism), /etc/nologin may or may not function as you expect it to.
 *   With sshd_config UseLogin no (default), UsePAM yes (& sshd built with PAM),
 *   and pam_nologin.so commented out in /etc/pam.d/sshd, the contents of
 *   /etc/nologin will be printed to users when logging in to a login shell,
 *   and access will be denied but no /etc/nologin printed when non-interactive
 *   command (e.g. sftp).  (This is so that the client does not mistake the
 *   contents of /etc/nologin for the output of the non-interactive command.)
 *   On the other hand, if UseLogin yes, then leave pam_nologin.so enabled in
 *   /etc/pam.d/sshd and logins will be disabled, but the contents of 
 *   /etc/nologin will _not_ be displayed, and users will be prompted for their
 *   passwords three times before being locked out, with no indication that
 *   logins are disabled, just a message that keyboard interactive login failed.
 *
 * Be cautious about adding programs to be available via this shell.  Note that
 *   I make no guarantees to filter out all undesirable options from any 
 *   featureful programs, including scp, rsync, and unison.  If you wish to
 *   disable any program, simply do not include it in CHROOTED_CMD_DIR
 *   In short, the most restrictive installations using chressh will only allow
 *   sftp-server to be executed (only place sftp-server in CHROOTED_CMD_DIR)
 *
 * The current set of programs do not appear to need any device files in the
 *   chroot, so the partition containing restricted user homes can be mounted 
 *   with the nodev option.  If programs do need things like /dev/null, then
 *   this is not possible and /dev/null (or other device files) must be created
 *   within the chroot.
 *
 * Do note that if a user has access to other methods to run custom programs,
 *   such as the ability to upload CGI or PHP programs, then the benefits of
 *   the restrictions imposed by chressh are somewhat eroded.
 *
 * Choices for setting up target programs in CHROOTED_CMD_DIR:
 * Hard-link statically-linked sftp-server into users' chroot
 *     $HOME/<CHROOTED_CMD_DIR>sftp-server
 *   Upgrading a hard-linked sftp-server requires editing it in-place:
 *   Temporarily disallow logins by placing a nologin file in the appropriate
 *     location (e.g. /etc/nologin).  (This disables non-root ssh logins, too.)
 *   Write to sftp-server in-place and truncate file at end of writing.
 *     cat new-sftp-server > sftp-server
 *   Remove the nologin file to re-enable logins.
 * Alternatively, hard link the directory containing the static executables
 *   (e.g. ~/.chressh/bin/).  All the usual caveats to hard linking directories
 *   apply, but this allows an executable to be upgraded without affecting
 *   sessions currently in progress.  (New sessions will get the new executable
 *   while the old deleted one will disappear once it is no longer in use.)
 *   ? Is hard linking directories inside a chroot a bad idea?
 * Finally, if statically compiled programs are small, such as when linked
 *   against dietlibc, just copy the files into each chroot.  Upgrades will
 *   have to update all the chroots, but that is easily scripted.  This is the
 *   recommended method unless you are really, really disk space restricted.
 *
 * chdir() to home is performed after chroot() and dropping privileges in case
 *   homedir is located over a root-restricted NFS mount.  A chdir() to a
 *   fully-qualified path after a chroot() is required to ensure that current 
 *   working directory is within the chroot directory hierarchy.
 * stat() of chroot_dir before chroot() is vulnerable to race conditions
 *   (TOC-TOU).  However it is not intended to be secure in that sense;
 *   the stat() is only a quick sanity check for admin misconfigurations.
 *   It is the job of the admin to properly set up homes (e.g. user homedirs
 *   should be owned by root and have no write permissions; subdirs can be
 *   owned by user and writable by user, except for CHROOTED_CMD_DIR, of course)
 * openlog() is called with LOG_NDELAY before chroot() to connect to syslog
 *   daemon before losing access to /dev/log
 * command line shell parsing is performed after dropping privileges in case
 *   filesystem is on a root-restricted NFS mount, and because there is no 
 *   reason not to do this after dropping root privileges (as much code as
 *   possible should be run without privileges).  shell parsing is also after
 *   env_clean(), which updates HOME env var to new chroot dir if possible and
 *   puts a safer environment back into environ.
 *
 *
 * Future possible directions:
 * ---------------------------
 *
 * TODO:replace GLOB_NOCHECK with GLOB_NOMAGIC on platforms that have
 *	GLOB_NOMAGIC and test that it does what we expect
 *	Use GLOB_TILDE and GLOB_BRACE if platform has it (no-op if not)
 *	  (and, of course, use wordexp() instead, if available on the platform)
 * RFE: find reasonable address space memory limits for wordexp() or glob(),
 *	which is currently arbitrarily set to ARG_MAX<<5 in shell_parse()
 *	(ARG_MAX is 128 KB on Linux, and so ARG_MAX<<5 is 4 MB.  On some other
 *	 systems, ARG_MAX is 2 MB) (If program is unexpectedly dying
 *	 (closed connection) (with SIGSEGV), then this limit might be too low)
 * RFE: Instead of above, replace shell_parse() with a portable wordexp() that
 *	does not execute a subshell (as some wordexp() implementations do), and
 *	that aborts arg generation if ARG_MAX size of args is reached.
 * RFE: adjust resource limits to restrain target programs
 *	(after determining fair, operable limits)
 *	(e.g. unison might require ulimit for large stack size to be able
 *	 to synchronize directories with hundreds of thousands of files)
 * RFE: ? add bandwidth limiting arg to programs that support it?
 *      (later versions of OpenSSH scp and rsync)
 *	would need to parse if user provided arg and take lower of the two
 *	would need to leave space at beginning of array to add args later
 *      rsync --bwlimit 0 disables limit, also beware of large or negative nums
 *	(would need to shift args array over these values to eliminate them)
 * RFE: ? rsync/unison: add further arg parsing to disallow remote paths/proxies
 * RFE: ? unison: always add "-killserver" (already default for ssh connections)
 * RFE: log obvious attempts to subvert the shell
 *	(e.g. blatantly obvious bad command options to some programs)
 *
 *
 * Setup and Installation:
 * -----------------------
 * Compile and install chressh
	gcc -O3 -Wall -o chressh chressh.c
	install -s -o root -g root -m 4711 --backup=none \
	  chressh /usr/local/sbin/chressh
 *   chressh needs to be setuid root for chroot() to function (chmod 4711).
 *   Compile this shell to be static unless SSH user environment is restricted,
 *   e.g. 'PermitUserEnvironment no' (default in recent versions of OpenSSH)
 *   (gcc -O3 -Wall -static -o chressh chressh.c)
 *
 * Compile statically-linked programs against glibc for use within chroot.
 *
 * sftp-server and scp:
 *   http://www.openssh.com/
 *   (static sftp-server compiles cleanly on RedHat 9 and Fedora Core 1.
 *    RedHat 7.2 glibc has crashing bug (NULL pointer dereference)
 *    deep within library calls to getpw* and getgr*)
	tar xvzf openssl-0.9.7d.tar.gz
	cd openssl-0.9.7d
	./Configure linux-ppro
	make
	cd ..
	tar xvzf openssh-3.8p1.tar.gz
	cd openssh-3.8p1
	make distclean
	./configure --with-pam --with-ldflags=-static \
	  --with-ssl-dir=../openssl-0.9.7d
	make sftp-server scp
	strip sftp-server scp
 *   place sftp-server and scp in ~/<CHROOTED_CMD_DIR>
 *   scp requires /etc/{passwd,group} inside the chroot contain caller uid/gid
 *     (create these two files with entries (* passwd) just for caller uid/gid)
 *   (scp may or may not work when compiled statically against glibc;
 *    see dietlibc instructions below)
 *
 * rsync:
 *   http://rsync.samba.org/
	tar xvzf rsync-2.6.0.tar.gz
	cd rsync-2.6.0
	LDFLAGS=-static ./configure
	make
	strip rsync
 *   place rync in ~/<CHROOTED_CMD_DIR>
 *
 * unison:
 *   http://www.cis.upenn.edu/~bcpierce/unison/
 *   http://www.cis.upenn.edu/~bcpierce/unison/download/stable/latest/
 *   create ~/.unison sticky with group write permission (chmod +t,g+rwx)
 *     (and owned by root, not user)
 *   touch ~/.unison/default.prf  (leave empty, owned by root, no user write)
 *   download statically-compiled executable
 *   rename to unison and place unison in ~/<CHROOTED_CMD_DIR>
 *
 *
 * Alternatively, compile static programs against dietlibc.
 * (Instructions for unison remain the same)
 *
 *
 * dietlibc v0.25
 *   http://www.dietlibc.org/
 *   http://www.fefe.de/dietlibc/
 * (realpath() is broken in dietlibc v0.25;
 *  ./configure OpenSSH below with -DBROKEN_REALPATH in CFLAGS)
	cd /usr/local/src
	rm -rf dietlibc-0.25
	tar xvjf dietlibc-0.25.tar.bz2
	chown -R root.root dietlibc-0.25*
	cd dietlibc-0.25
	make
	DIET="/usr/local/src/dietlibc-0.25/bin-i386/diet gcc -pipe -nostdinc"
	DIET_INC="/usr/local/src/dietlibc-0.25/include"
 *
 * zlib v1.2.1
 *   http://www.gzip.org/zlib/
 *   (needed for compile of static sftp-server and scp with dietlibc)
 *   (dietlibc gives warnings about bloat and deprecation, which simplistic
 *    configure script treats as failures, so edit Makefile after ./configure)
	cd /usr/local/src
	rm -rf zlib-1.2.1
	tar xvjf zlib-1.2.1.tar.bz2
	chown -R root.root zlib-1.2.1*
	cd zlib-1.2.1
	CC="$DIET" CFLAGS=-D_BSD_SOURCE ./configure
	perl -pi -e 's|^CFLAGS=.*|CFLAGS=-O3 -D_BSD_SOURCE -DUSE_MMAP|' Makefile
	make
 *
 * openssl v0.9.7d
 *   http://www.openssl.org/
 *   (use latest version for compile of static sftp-server and scp)
 *   (openssl does not respect $CC, so we edit Makefile* after ./Configure)
 *   (only no-dso is required to ./Configure, but the way we use openssl static
 *    library, no-shared, no-hw, and no-engine are used; -march=i686 is passed)
 *   (optionally 'make test' after running 'make')
	cd /usr/local/src
	rm -rf openssl-0.9.7d
	tar xvzf openssl-0.9.7d.tar.gz
	chown -R root.root openssl-0.9.7d*
	cd openssl-0.9.7d
	./Configure linux-ppro no-dso no-shared no-hw no-engine -march=i686
	perl -pi -e \
	  "s|^CC=.*|CC=$DIET|, \
	   s|^MAKEDEPPROG=.*|MAKEDEPPROG= gcc -pipe -nostdinc -I$DIET_INC|" \
	  `find . -name Makefile\*`
	make depend
	make
 *
 * openssh v3.8p1
 *   scp requires that chroot contain /etc/passwd and /etc/group (?)
 *   no passwords, no shadows -- just so that it can verify that uid exists
	cd /usr/local/src
	rm -rf openssh-3.8p1
	tar xvzf openssh-3.8p1.tar.gz
	chown -R root.root openssh-3.8p1*
	cd openssh-3.8p1
	CC="$DIET" CFLAGS=-D_BSD_SOURCE \
	  ./configure --sysconfdir=/.ssh \
	  --with-ssl-dir=/usr/local/src/openssl-0.9.7d \
	  --with-zlib=/usr/local/src/zlib-1.2.1 \
	  --disable-nls --disable-shared --enable-static
	make sftp-server scp
	strip sftp-server scp
 *
 * rsync v2.6.0
 *   http://rsync.samba.org/
	cd /usr/local/src
	rm -rf rsync-2.6.0
	tar xvzf rsync-2.6.0.tar.gz
	chown -R root.root rsync-2.6.0*
	cd rsync-2.6.0
	CC="$DIET" ./configure --disable-nls --disable-shared --enable-static
	make
	strip rsync
 */
