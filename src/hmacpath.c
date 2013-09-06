/* hmacpath.c */
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

#include <stdlib.h>
#include <string.h>

#include "filehmac.h"

char *
make_hmac_path(const char *origpath, const char *destdir, const char *hmac_suffix)
{
	char *path, *p;
	const char *fn;
	size_t len;

	if (hmac_suffix == NULL) {
		hmac_suffix = HMAC_SUFFIX;
	}

	fn = strrchr(origpath, '/');
	if (fn == NULL) {
		fn = origpath;
	} else {
		++fn;
	}

	if (destdir == NULL) {
		len = sizeof(HMAC_PREFIX) + strlen(hmac_suffix) + strlen(origpath) + 1;
	}
	else {
		len = strlen(hmac_suffix) + strlen(fn) + strlen(destdir) + 2;
	}

	path = malloc(len);
	if(path == NULL) {
		return NULL;
	}

	if (destdir == NULL) {
		strncpy(path, origpath, fn-origpath);
		p = path + (fn - origpath);
		p = stpcpy(p, HMAC_PREFIX);
	} else {
		p = stpcpy(path, destdir);
		if (p != path && *(p-1) != '/') {
			p = stpcpy(p, "/");
		}
	}
	p = stpcpy(p, fn);
	p = stpcpy(p, hmac_suffix);

	return path;
}
