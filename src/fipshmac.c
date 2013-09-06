/* fipshmac.c */
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
#include <string.h>
#include <unistd.h>

#include "filehmac.h"

static int
create_hmac(const char *path, const char *destdir, const char *hmac_suffix)
{
	FILE *hf;
	char *hmacpath;
	int rv = 0;
	char *hmac = NULL;
	size_t hmaclen;
	void *buf;
	char *hex;

	hmacpath = make_hmac_path(path, destdir, hmac_suffix);

	if (hmacpath == NULL) {
		debug_log("Cannot make hmac path");
		return 5;
	}

	hf = fopen(hmacpath, "w");
	if (hf == NULL) {
		debug_log("Cannot open hmac file '%s'", hmacpath);
		free(hmacpath);
		return 3;
	}

	if (compute_file_hmac(path, &buf, &hmaclen, 0) < 0) {
		rv = 4;
		goto end;
	}

	if ((hex=bin2hex(buf, hmaclen)) == NULL) {
		debug_log("Cannot convert hmac to hexadecimal");
		free(buf);
		rv = 5;
		goto end;
	}

	if (fprintf(hf, "%s\n", hex) < hmaclen*2) {
		debug_log("Cannot write to hmac file '%s'", hmacpath);
		rv = 6;
	}

	free(buf);
	free(hex);

end:
	free(hmac);
	if (fclose(hf) != 0) {
		debug_log("Failure during closing hmac file '%s'", hmacpath);
		rv = 7;
	}
	if (rv != 0) {
		unlink(hmacpath);
	}
	free(hmacpath);

	return rv;
}

int
main(int argc, char *argv[])
{
	int i, j = 1;
	const char *destdir = NULL;
	const char *hmac_suffix = NULL;

	if (argc < 2) {
		fprintf(stderr, "usage: fipshmac [-d <dir>] <paths-to-files>\n");
		return 2;
	}

	debug_log_stderr();

	if (strcmp(argv[1], "-d") == 0) {
		j += 2;
		if (argc < 4) {
			fprintf(stderr, "Missing destination directory.\n");
			return 2;
		}
		destdir = argv[2];
	}

	for (i = j; i < argc; i++) {
		if (strcmp(argv[i], "-s") == 0) {
			i++;
			if (i >= argc) {
				fprintf(stderr, "Missing argument of the -s option\n");
				return 2;
			}
			hmac_suffix = argv[i];
		}
	}

	for (i = j; argv[i] != NULL; i++) {
		int rv;

		if (strcmp(argv[i], "-s") == 0) {
			i++;
			continue;
		}
		if ((rv=create_hmac(argv[i], destdir, hmac_suffix)) != 0)
			return rv;
	}

	return 0;
}
