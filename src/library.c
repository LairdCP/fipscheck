/* library.c */
/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY RED HAT, INC. ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE FREEBSD PROJECT OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of Red Hat, Inc.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "fipscheck.h"
#include "filehmac.h"

#define MAX_PATH_LEN 4096
#define SELFLINK "/proc/self/exe"
#ifndef PATH_FIPSCHECK
#define PATH_FIPSCHECK "/usr/bin/fipscheck"
#endif
#define FIPS_MODE_SWITCH_FILE "/proc/sys/crypto/fips_enabled"

int
FIPSCHECK_get_binary_path(char *path, size_t pathlen)
{
	ssize_t len;

	len = readlink(SELFLINK, path, pathlen-1);
	
	if (len < 0) {
		return -1;
	}
	
	path[len] = '\0';
	return 0;
}


int
FIPSCHECK_get_library_path(const char *libname, const char *symbolname, char *path, size_t pathlen)
{
	Dl_info info;
	void *dl, *sym;
	int rv = -1;

        dl = dlopen(libname, RTLD_NODELETE|RTLD_NOLOAD|RTLD_LAZY);
        if (dl == NULL) {
	        return -1;
        }       

	sym = dlsym(dl, symbolname);

	if (sym != NULL && dladdr(sym, &info)) {
		strncpy(path, info.dli_fname, pathlen-1);
		path[pathlen-1] = '\0';
		rv = 0;
	}

	dlclose(dl);
	
	return rv;
}


static int
run_fipscheck_helper(const char *hmac_suffix, const char *paths[])
{
	int rv = -1, child;
	void (*sighandler)(int) = NULL;

	sighandler = signal(SIGCHLD, SIG_DFL);

	/* fork */
	child = fork();
	if (child == 0) {
		static char *envp[] = { NULL };
		char **args;
		int i, offset = 1;

		for (i = 0; paths[i] != NULL; i++);

		if (i < 1) /* nothing to check */
			_exit(127);

		args = calloc(i + 4, sizeof(*args));

		if (args == NULL)
			_exit(127);

		args[0] = PATH_FIPSCHECK;
		if (hmac_suffix) {
			args[1] = "-s";
			args[2] = (char *)hmac_suffix;
			offset = 3;
		}
		memcpy(&args[offset], paths, sizeof(*args)*(i + 1));

		execve(PATH_FIPSCHECK, args, envp);

		/* if we get here: exit with error */
		_exit(127);

	} else if (child > 0) {
		int status;

		while ((rv=waitpid(child, &status, 0)) == -1 &&   /* wait for fipscheck to complete */
			errno == EINTR);
		if (rv > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			rv = 0;
		} else {
			rv = -1;
		}
	} /* else failed fork */

	if (sighandler != SIG_ERR) {
		(void) signal(SIGCHLD, sighandler);   /* restore old signal handler */
	}

	return rv;
}

static int
test_hmac_installed(const char *path, const char *hmac_suffix)
{
	const char *hmacdir = PATH_HMACDIR;
	char *hmacpath;
	int rv;

	do {
		hmacpath = make_hmac_path(path, hmacdir, hmac_suffix);
		if (hmacpath == NULL) {
			/* we must fail later */
			return 1;
		}

		rv = access(hmacpath, F_OK);
		if (rv < 0 && errno != ENOENT) {
			rv = 0;
		}

		free(hmacpath);

		if (rv < 0 && hmacdir == NULL) {
			/* hmac not found */
			return 0;
		}

		hmacdir = NULL;
        } while (rv < 0);
	/* hmac found */
        return 1;
}

int
FIPSCHECK_verify(const char *libname, const char *symbolname)
{
	return FIPSCHECK_verify_ex(libname, symbolname, NULL, 1);
}

int
FIPSCHECK_verify_ex(const char *libname, const char *symbolname, const char *hmac_suffix, int fail_if_missing)
{
	char path[MAX_PATH_LEN];
	const char *files[] = {path, NULL};
	int rv;

	if (libname == NULL || symbolname == NULL) {
		rv = FIPSCHECK_get_binary_path(path, sizeof(path));
	} else {
		rv = FIPSCHECK_get_library_path(libname, symbolname, path, sizeof(path));
	}

	if (rv < 0)
		return 0;

	if (!fail_if_missing && !test_hmac_installed(path, hmac_suffix))
		return 1;

	rv = run_fipscheck_helper(hmac_suffix, files);

	if (rv < 0)
		return 0;

	/* check successful */
	return 1;
}

int
FIPSCHECK_verify_files(const char *files[])
{
	return FIPSCHECK_verify_files_ex(NULL, 1, files);
}

int
FIPSCHECK_verify_files_ex(const char *hmac_suffix, int fail_if_missing, const char *files[])
{
	int rv;

	if (!fail_if_missing && !test_hmac_installed(files[0], hmac_suffix))
		return 1;

	rv = run_fipscheck_helper(hmac_suffix, files);

	if (rv < 0)
		return 0;

	return 1;
}

int
FIPSCHECK_fips_module_installed(const char *libname, const char *symbolname, const char *hmac_suffix)
{
	char path[MAX_PATH_LEN];
	int rv;

	if (libname == NULL || symbolname == NULL) {
		rv = FIPSCHECK_get_binary_path(path, sizeof(path));
	} else {
		rv = FIPSCHECK_get_library_path(libname, symbolname, path, sizeof(path));
	}

	if (rv < 0)
		/* Fail safe - that is as if the module was installed */
		return 1;

	return test_hmac_installed(path, hmac_suffix);
}

int
FIPSCHECK_kernel_fips_mode(void)
{
	int fd;
	char buf[1] = "";

	if ((fd=open(FIPS_MODE_SWITCH_FILE, O_RDONLY)) >= 0) {
		while (read(fd, buf, sizeof(buf)) < 0 && errno == EINTR);
		close(fd);
	}
	if (buf[0] == '1')
		return 1;
	return 0;
}
