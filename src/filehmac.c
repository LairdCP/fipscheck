/* filehmac.c */
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
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <openssl/fips.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "filehmac.h"

#define READ_BUFFER_LENGTH 16384

static const char hmackey[] = "orboDeJITITejsirpADONivirpUkvarP";

#define DEBUG_LOG_SYSLOG 1
#define DEBUG_LOG_STDERR 2

#define DEBUG_LOG_ENVVAR "FIPSCHECK_DEBUG"

static int log_dest;

static const char alloc_msg[] = "Memory allocation error";

void
debug_log_getenv(void)
{
	char *dbgenv;

	dbgenv = getenv(DEBUG_LOG_ENVVAR);
	if (dbgenv != NULL) {
		if (strcasecmp(dbgenv, "syslog") == 0)
			log_dest = DEBUG_LOG_SYSLOG;
		else if (strcasecmp(dbgenv, "stderr") == 0 ||
			 strcasecmp(dbgenv, "error") == 0)
			log_dest = DEBUG_LOG_STDERR;
	}
}

void
debug_log(const char *fmt, ...)
{
	va_list args;
	int save_errno = errno;
	char *msg;

	if (!log_dest)
		return;

	va_start(args, fmt);

	if (vasprintf(&msg, fmt, args) < 0)
		msg = (char *)alloc_msg;

	va_end(args);

	if (log_dest & DEBUG_LOG_SYSLOG) {
		if (save_errno != 0)
			syslog(LOG_ERR, "%s : %s", msg, strerror(save_errno));
		else
			syslog(LOG_ERR, "%s", msg);
	}

	if (log_dest & DEBUG_LOG_STDERR) {
		if (save_errno != 0)
			fprintf(stderr, "fipscheck: %s : %s\n", msg, strerror(save_errno));
		else
			fprintf(stderr, "fipscheck: %s\n", msg);
	}

	if (msg != alloc_msg)
		free(msg);
}


void
debug_log_stderr(void)
{
	log_dest = DEBUG_LOG_STDERR;
}

#ifdef CALL_PRELINK
static FILE *
spawn_prelink(const char *path, int *prelink)
{
	FILE *rpipe;
	int child;
	int fds[2];

	*prelink = 0;

	if (pipe(fds) != 0) {
		return NULL;
	}

	child = fork();

	if (child == 0) {
		char * args[] = { NULL, NULL, NULL, NULL };

		args[0] = PATH_PRELINK;
		args[1] = "--verify";
		args[2] = (char *)path;

		close(fds[0]);
		if (dup2(fds[1], STDOUT_FILENO) == -1) {
		    exit(126);
		}

		execv(PATH_PRELINK, args);
		/* if we get here: exit with error */
		exit(127);
	} else if (child > 0) {
		*prelink = child;
		
		close(fds[1]);
		rpipe = fdopen(fds[0], "r");
		return rpipe;
	}

	/* fork failed */
	close(fds[0]);
	close(fds[1]);
	return NULL;
}
#endif

int
compute_file_hmac(const char *path, void **buf, size_t *hmaclen, int force_fips)
{
	FILE *f = NULL;
#ifdef CALL_PRELINK
	int prelink = 0;
#endif
	int rv = -1;
	HMAC_CTX c;
	unsigned char rbuf[READ_BUFFER_LENGTH];
	size_t len;
	unsigned int hlen;

	if (force_fips && !FIPS_mode()) {
		if (!FIPS_mode_set(1)) {
			debug_log("FIPS_mode_set() failed");
			return -1;
		}
	}

	HMAC_CTX_init(&c);

#ifdef CALL_PRELINK
	if (access(PATH_PRELINK, X_OK) == 0) {
		f = spawn_prelink(path, &prelink);
	}

	if (!prelink && f == NULL) {
#endif
		f = fopen(path, "r");
#ifdef CALL_PRELINK
	}
#endif

	if (f == NULL) {
		debug_log("Failed to open '%s'", path);
		goto end;
	}

	HMAC_Init(&c, hmackey, sizeof(hmackey)-1, EVP_sha256());

	while ((len=fread(rbuf, 1, sizeof(rbuf), f)) != 0) {
		HMAC_Update(&c, rbuf, len);
	}

	len = sizeof(rbuf);
	/* reuse rbuf for hmac */
	HMAC_Final(&c, rbuf, &hlen);

	*buf = malloc(hlen);
	if (*buf == NULL) {
		debug_log("Failed to allocate memory");
		goto end;
	}

	*hmaclen = hlen;

	memcpy(*buf, rbuf, hlen);

	rv = 0;
end:
	HMAC_CTX_cleanup(&c);

	if (f)
		fclose(f);

#ifdef CALL_PRELINK
	if (prelink) {
		int ret;
		int status;

		while ((ret=waitpid(prelink, &status, 0)) == -1 &&   /* wait for prelink to complete */
			errno == EINTR);
		if (ret <= 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			debug_log("prelink failed");
			rv = -1;
		}
	}
#endif

	return rv;
}

static const char conv[] = "0123456789abcdef";

char *
bin2hex(void *buf, size_t len)
{
	char *hex, *p;
	unsigned char *src = buf;
	
	hex = malloc(len * 2 + 1);
	if (hex == NULL)
		return NULL;

	p = hex;

	while (len > 0) {
		unsigned c;

		c = *src;
		src++;

		*p = conv[c >> 4];
		++p;
		*p = conv[c & 0x0f];
		++p;
		--len;
	}
	*p = '\0';
	return hex;
}
