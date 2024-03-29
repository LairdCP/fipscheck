/* fipscheck.c */
/*
 * Copyright (C) 2008, 2009, 2010, 2012, 2013 Red Hat Inc. All rights reserved.
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
#include <string.h>
#include <errno.h>

#include "filehmac.h"
#include "fipscheck.h"

#define MAX_HMAC_LEN 1024

static int
verify_hmac(const char *path, const char *hmac_suffix)
{
	FILE *hf = NULL;
	char *hmacpath, *p;
	int rv = 1;
	char hmac[MAX_HMAC_LEN];
	size_t n;
	const char *hmacdir = PATH_HMACDIR;

	do {
		hmacpath = make_hmac_path(path, hmacdir, hmac_suffix);
		if (hmacpath == NULL) {
			debug_log("Cannot make hmac path");
			return 5;
		}

		hf = fopen(hmacpath, "r");
		if (hf == NULL && hmacdir == NULL) {
			debug_log("Cannot open hmac file '%s'", hmacpath);
			free(hmacpath);
			return 3;
		}

		free(hmacpath);
		hmacdir = NULL;
	} while (hf == NULL);

	if (fgets(hmac, sizeof(hmac), hf) != NULL) {
		void *buf;
		size_t hmaclen;
		char *hex;

		if ((p=strchr(hmac, '\n')) != NULL)
			*p = '\0';

		if (compute_file_hmac(path, &buf, &hmaclen, 1) < 0) {
			rv = 4;
			goto end;
		}

		if ((hex=bin2hex(buf, hmaclen)) == NULL) {
			errno = 0;
			debug_log("Cannot convert hmac to hexadecimal");
			free(buf);
			rv = 5;
			goto end;
		}

		if (strcmp(hex, hmac) != 0) {
			errno = 0;
			debug_log("Hmac mismatch on file '%s'", path);
		} else {
			/* checksum matched */
			rv = 0;
		}
		free(buf);
		free(hex);
	} else {
		debug_log("Empty or broken hmac on file '%s'", path);
	}

end:
	fclose(hf);
	return rv;
}

int
main(int argc, char *argv[])
{
	int rv, i;
	char buf[4096];
	const char *hmac_suffix = NULL;

	if (argc < 2) {
		fprintf(stderr, "usage: fipscheck [-s <hmac-suffix>] <paths-to-files>\n");
		fprintf(stdout,"fips mode is %s\n", 
			FIPSCHECK_kernel_fips_mode() ? "on" : "off" );
		return 2;
	}

	debug_log_getenv();

	if (FIPSCHECK_get_library_path("libfipscheck.so.1",
		"FIPSCHECK_get_library_path", buf, sizeof(buf)) != 0) {
		debug_log("FIPSCHECK_get_library_path() failed");
		return 10;
	}

	if ((rv=verify_hmac(buf, NULL)) != 0) {
		return rv+10;
	}

	if (FIPSCHECK_get_binary_path(buf, sizeof(buf)) != 0) {
		debug_log("FIPSCHECK_get_binary_path() failed");
		return 20;
	}

	if ((rv=verify_hmac(buf, NULL)) != 0) {
		return rv+20;
	}

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-s") == 0) {
			i++;
			if (i >= argc) {
				fprintf(stderr, "Missing argument of the -s option\n");
				return 2;
			}
			hmac_suffix = argv[i];
		}
	}

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-s") == 0) {
			i++;
			continue;
		}
		rv = verify_hmac(argv[i], hmac_suffix);
		if (rv != 0) {
			return rv;
		}
	}

	return 0;
}
