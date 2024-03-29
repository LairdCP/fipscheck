/* filehmac.c */
/*
 * Copyright (C) 2008, 2009, 2010, 2013 Red Hat Inc. All rights reserved.
 * Copyright (C) 2016 Andrew Cagney
 *
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

#if defined(WITH_OPENSSL)
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#include <openssl/evp.h>
#else
#include <openssl/hmac.h>
#endif
#elif defined(WITH_NSS)
#include <nss.h>
#include <sechash.h>
#include <alghmac.h>
#include <pk11pub.h>
#include <secmod.h>
#else
#error "no crypto library defined"
#endif

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

#if defined(WITH_OPENSSL) && OPENSSL_VERSION_NUMBER < 0x10100000L

#define HMAC_CTX_new compat_hmac_ctx_new
static HMAC_CTX *
compat_hmac_ctx_new()
{
	HMAC_CTX *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx != NULL)
		HMAC_CTX_init(ctx);
	return ctx;
}

#define HMAC_CTX_free compat_hmac_ctx_free
static void
compat_hmac_ctx_free(HMAC_CTX *ctx)
{
	HMAC_CTX_cleanup(ctx);
	free(ctx);
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

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
		char *args[] = { NULL, NULL, NULL, NULL };

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

#if defined(WITH_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L
int
compute_file_hmac(const char *path, void **buf, size_t *hmaclen, int force_fips)
{
	static OSSL_PROVIDER *fips = NULL;
	FILE *f = NULL;

#ifdef CALL_PRELINK
	int prelink = 0;
#endif
	int rv = -1;
	OSSL_PARAM params[2];
	unsigned char rbuf[READ_BUFFER_LENGTH];
	size_t len;
	size_t hlen;

	if (force_fips && fips == NULL) {
		fips = OSSL_PROVIDER_load(NULL, "fips");
		if (fips == NULL) {
			debug_log("Failed to load FIPS provider\n");
			return -1;
		}
	}

#ifdef CALL_PRELINK
	if (access(PATH_PRELINK, X_OK) == 0) {
		f = spawn_prelink(path, &prelink);
	}

	if (!prelink && f == NULL) {
		f = fopen(path, "r");
	}
#else
	f = fopen(path, "r");
#endif

	if (f == NULL) {
		debug_log("Failed to open '%s'", path);
		goto end;
	}

	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", force_fips ? "provider=fips" : NULL);
	if (mac == NULL) {
		debug_log("Failed to allocate memory for HMAC");
		goto end;
	}

	EVP_MAC_CTX *c = EVP_MAC_CTX_new(mac);
	if (c == NULL) {
		debug_log("Failed to allocate memory for HMAC_CTX");
		goto end;
	}

	EVP_MAC_free(mac);

	params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
	params[1] = OSSL_PARAM_construct_end();

	EVP_MAC_init(c, hmackey, sizeof(hmackey) - 1, params);

	while ((len = fread(rbuf, 1, sizeof(rbuf), f)) != 0)
		EVP_MAC_update(c, rbuf, len);

	EVP_MAC_final(c, rbuf, &hlen, sizeof(rbuf));
	EVP_MAC_CTX_free(c);

	*buf = malloc(hlen);
	if (*buf == NULL) {
		debug_log("Failed to allocate memory");
		goto end;
	}

	*hmaclen = hlen;

	memcpy(*buf, rbuf, hlen);

	rv = 0;

end:
	if (f)
		fclose(f);

#ifdef CALL_PRELINK
	if (prelink) {
		int ret;
		int status;

		while ((ret = waitpid(prelink, &status, 0)) == -1 &&   /* wait for prelink to complete */
		       errno == EINTR);
		if (ret <= 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			debug_log("prelink failed");
			rv = -1;
		}
	}
#endif

	return rv;
}
#else
int
compute_file_hmac(const char *path, void **buf, size_t *hmaclen, int force_fips)
{
	FILE *f = NULL;

#ifdef CALL_PRELINK
	int prelink = 0;
#endif
	int rv = -1;
#if defined(WITH_OPENSSL)
	HMAC_CTX *c = NULL;
#elif defined(WITH_NSS)
	HMACContext *c = NULL;
	const SECHashObject *hash;
#endif
	unsigned char rbuf[READ_BUFFER_LENGTH];
	size_t len;
	unsigned int hlen;

#if defined(WITH_NSS)
	/*
	 * While, technically, NSS_NoDB_Init() is idempotent, perform
	 * an explicit test.
	 */
	if (!NSS_IsInitialized()) {
		NSS_NoDB_Init(".");
	}
#endif

	if (force_fips) {
#if defined(WITH_OPENSSL)
		if (!FIPS_mode()) {
			if (!FIPS_mode_set(1)) {
				debug_log("FIPS_mode_set() failed");
				return -1;
			}
		}
#elif defined(WITH_NSS)
		if (!PK11_IsFIPS()) {
			SECMODModule *internal = SECMOD_GetInternalModule();
			if (internal == NULL) {
				errno = 0;
				debug_log("SECMOD_GetInternalModule() failed");
				return -1;
			}
			if (SECMOD_DeleteInternalModule(internal->commonName) != SECSuccess) {
				errno = 0;
				debug_log("SECMOD_DeleteInternalModule(%s) failed",
					  internal->commonName);
				return -1;
			}
			if (!PK11_IsFIPS()) {
				errno = 0;
				debug_log("NSS FIPS mode toggle failed");
				return -1;
			}
		}
#endif
	}

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

#if defined(WITH_OPENSSL)
	c = HMAC_CTX_new();
	if (c == NULL) {
		debug_log("Failed to allocate memory for HMAC_CTX");
		goto end;
	}
	HMAC_Init_ex(c, hmackey, sizeof(hmackey) - 1, EVP_sha256(), NULL);
#elif defined(WITH_NSS)
	errno = 0;
	hash = HASH_GetHashObject(HASH_AlgSHA256);
	if (hash == NULL) {
		errno = 0;
		debug_log("HASH_GetHashObject(HASH_AlgSHA256) failed");
		goto end;
	}
	c = HMAC_Create(hash, hmackey, sizeof(hmackey) - 1,
			force_fips ? PR_TRUE : PR_FALSE);
	if (c == NULL) {
		errno = 0;
		debug_log("HMAC_Create() failed");
		goto end;
	}
	HMAC_Begin(c);
#endif

	while ((len = fread(rbuf, 1, sizeof(rbuf), f)) != 0)
		HMAC_Update(c, rbuf, len);

	len = sizeof(rbuf);
	/* reuse rbuf for hmac */
#if defined(WITH_OPENSSL)
	HMAC_Final(c, rbuf, &hlen);
#elif defined(WITH_NSS)
	HMAC_Finish(c, rbuf, &hlen, sizeof(rbuf) - 1);
#endif

	*buf = malloc(hlen);
	if (*buf == NULL) {
		debug_log("Failed to allocate memory");
		goto end;
	}

	*hmaclen = hlen;

	memcpy(*buf, rbuf, hlen);

	rv = 0;
end:
	if (c != NULL) {
#if defined(WITH_OPENSSL)
		HMAC_CTX_free(c);
#elif defined(WITH_NSS)
		HMAC_Destroy(c, PR_TRUE);
#endif
	}

	if (f)
		fclose(f);

#ifdef CALL_PRELINK
	if (prelink) {
		int ret;
		int status;

		while ((ret = waitpid(prelink, &status, 0)) == -1 &&   /* wait for prelink to complete */
		       errno == EINTR);
		if (ret <= 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			debug_log("prelink failed");
			rv = -1;
		}
	}
#endif

	return rv;
}
#endif

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
