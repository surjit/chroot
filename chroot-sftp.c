/* chroot-sftp.c
 *   restricted (non-)login shell to allow (non-shell) users SFTP access
 *
 *   This is the original concept version for chressh.c
 *   Please see http://www.gluelogic.com/code/chressh/
 *   for notes, installation instructions, and gotchas
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
 *
 *
 * 2003.10.?? v0.02
 * Thanks to alpha auditors: Brian Fisk and others
 */

/* user's shell in passwd database MUST match this hard-coded path
 * (this is for the same reason that the system allows only root to chroot())
 */
#define CHROOTING_SHELL "/usr/local/sbin/chroot-sftp"

/* chrooted path to sftp-server program (relative to starting dir (homedir)) */
#define CHROOTED_PATH_SFTP_SERVER ".ssh/sftp-server"

/* chroot dir instead of homedir when user is a member of multiple groups
 * (user's homedir must be beneath this directory or else this is not used)
 * (This program will chroot to homedir if user is member of only one group)
 * (Include the trailing slash for a full directory path segment prefix match.
 *  While the GROUP_CHROOT_DIR then will not match if homedir is identical to
 *  GROUP_CHROOT_DIR (without a trailing slash), the results will be the same:
 *  chroot()ing to the homedir (which is the same dir as GROUP_CHROOT_DIR))
 */
#define GROUP_CHROOT_DIR "/nonexistent/"  /* set to bogus dir to disable */
/* #define GROUP_CHROOT_DIR "/pub/" */

/* umask default */
#define UMASK 0022
/* #define UMASK 0002 */  /* useful in web environments based around groups */


#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
extern char **environ;
extern int errno;

/* informative message to return if a system call failed */
#define SYSTEM_ERROR_MESG \
  "\n\tA system error occurred while attempting to execute sftp-server.\n" \
  "\n\tContact the systems administrator for further assistance.\n\n"
/* informative message to return if a this program is not user's shell */
#define SHELL_MISMATCH_MESG \
  "\n\tYou are not permitted to call this program.\n" \
  "\n\tContact the systems administrator for further assistance.\n\n"
/* informative message to return if login attempt is made */
#define NOLOGIN_MESG \
  "\n\tYou do not have interactive login access to this machine." \
  "\n\tContact the systems administrator for further assistance.\n\n"
/* informative message to return if invalid args passed */
#define BAD_ARGS_MESG \
  "\n\tInvalid arguments; command not allowed.  Only sftp-server accepted." \
  "\n\tContact the systems administrator for further assistance.\n\n"
#define ROOT_RUID_MESG \
  "\n\treal UID (target UID) of root is not allowed\n\n"

void
fatal(int argc, struct passwd *pw)
{
    int s_errno = errno;
    int fd = isatty(STDERR_FILENO) ? STDERR_FILENO : STDOUT_FILENO;
    openlog("chroot-sftp", LOG_PID, LOG_AUTHPRIV);

    if (s_errno) {
	syslog( LOG_NOTICE, "system error occurred for uid %lu (%s) (%s)",
		(unsigned long) getuid(), pw?pw->pw_name:"", strerror(s_errno));
	write(fd, SYSTEM_ERROR_MESG, sizeof(SYSTEM_ERROR_MESG)-1);
	exit(s_errno);
    }
    else if (NULL == pw) {
	syslog( LOG_NOTICE, "login attempted by invalid uid %lu",
		(unsigned long) getuid());
	write(fd, NOLOGIN_MESG, sizeof(NOLOGIN_MESG)-1);
    }
    else if (0 == getuid()) {
	syslog( LOG_NOTICE, "real UID (target UID) of root is not allowed");
	write(fd, ROOT_RUID_MESG, sizeof(ROOT_RUID_MESG)-1);
    }
    else if (0 != memcmp(pw->pw_shell,CHROOTING_SHELL,sizeof(CHROOTING_SHELL))){
	syslog( LOG_NOTICE, "shell mismatch by uid %lu (%s)",
		(unsigned long) getuid(), pw->pw_name);
	write(fd, SHELL_MISMATCH_MESG, sizeof(SHELL_MISMATCH_MESG)-1);
    }
    else if (argc == 1) {
	syslog( LOG_NOTICE, "login attempted by uid %lu (%s)",
		(unsigned long) getuid(), pw->pw_name);
	write(fd, NOLOGIN_MESG, sizeof(NOLOGIN_MESG)-1);
    }
    else {
	syslog( LOG_NOTICE, "bad args passed by uid %lu (%s)",
		(unsigned long) getuid(), pw->pw_name);
	write(fd, BAD_ARGS_MESG, sizeof(BAD_ARGS_MESG)-1);
    }
    sleep(3);
    exit(1);
}

int
main(int argc, char *argv[])
{
    struct passwd *pw;
    size_t len;
    char *empty_env[]   = { NULL };
    char *target_argv[] = { "sftp-server", NULL };
    char **target_env   = environ;
    environ = empty_env;

    if (NULL != (pw = getpwuid(getuid()))
	&& 0 != getuid()	/* always deny if real UID is root */
	&& 3 == argc		/* ("chroot-sftp -c /path/to/sftp-server") */
	&& 0 == memcmp(argv[1], "-c", 3)
	&& 11<= (len = strlen(argv[2]))	/* (strlen("sftp-server") == 11) */
	&& 0 == memcmp(argv[2]+len-11, "sftp-server", 11)
	&& 0 == memcmp(pw->pw_shell,CHROOTING_SHELL,sizeof(CHROOTING_SHELL))
	&& 0 == chdir (pw->pw_dir)) {
	char *chroot_dir = pw->pw_dir;
	if (0 == memcmp(pw->pw_dir,GROUP_CHROOT_DIR,sizeof(GROUP_CHROOT_DIR)-1)
	    && getgroups(0, (gid_t *) NULL) > 1)
	    chroot_dir = GROUP_CHROOT_DIR;
	openlog("chroot-sftp", LOG_NDELAY|LOG_PID, LOG_AUTHPRIV);/*(b4 chroot)*/
	if (0 == chroot(chroot_dir) && 0 == setuid(getuid())) {
	    umask(UMASK);
	    execve(CHROOTED_PATH_SFTP_SERVER, target_argv, target_env);
	}
    }
    fatal(argc, pw);
    return 0; /*(UNREACHED)*/
}
