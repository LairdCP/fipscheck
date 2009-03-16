/* fipscheck.c */
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

#include "filehmac.h"

int main(int argc, char *argv[])
{
	FILE *hf;
	char *hmacpath, *p;
	int rv = 0;
	char *hmac = NULL;
	size_t n;

	if (argc < 2) {
		fprintf(stderr, "usage: fipscheck <path-to-file>\n");
		return 2;
	}

	hmacpath = make_hmac_path(argv[1]);

	hf = fopen(hmacpath, "r");
	if (hf == NULL) {
		free(hmacpath);
		return 3;
	}

	if (getline(&hmac, &n, hf) > 0) {
		void *buf;
		size_t hmaclen;
		char *hex;

		if ((p=strchr(hmac, '\n')) != NULL)
			*p = '\0';

		if (compute_file_hmac(argv[1], &buf, &hmaclen) < 0) {
			rv = 4;
			goto end;
		}

		if ((hex=bin2hex(buf, hmaclen)) == NULL) {
			free(buf);
			rv = 5;
			goto end;
		}

		if (strcmp(hex, hmac) != 0) {
			rv = 1;
		}
		free(buf);
		free(hex);
	}

end:
	free(hmac);
	free(hmacpath);
	fclose(hf);
	return rv;
}
