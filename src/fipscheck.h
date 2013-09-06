/* fipscheck.h */
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

/* Verifies the HMAC checksum of the library or binary which contains the symbol.
 * If libname or symbolname is NULL, then the executable binary which is being
 * executed is verified. Verification fails if the checksum file is not found.
 * Return value: 0 - verification failed, 1 - verification succeded
 */
int FIPSCHECK_verify(const char *libname, const char *symbolname);

/* Verifies the HMAC checksum of the library or binary which contains the symbol.
 * If libname or symbolname is NULL, then the executable binary which is being
 * executed is verified. Non NULL hmac_suffix specifies the file name
 * suffix of the HMAC checksum file. fail_if_missing flag specifies
 * whether verification should fail if the checksum file is not found
 * Return value: 0 - verification failed, 1 - verification succeded
 */
int FIPSCHECK_verify_ex(const char *libname, const char *symbolname, const char *hmac_suffix, int fail_if_missing);

/* Verifies the HMAC checksum of the files in the NULL terminated array of
 * pointers. Fails if the hmacs are missing.
 * Return value: 0 - verification failed, 1 - verification succeded
 */
int FIPSCHECK_verify_files(const char *files[]);

/* Verifies the HMAC checksum of the files in the NULL terminated array of
 * pointers with possibility to specify the file name suffix and failure
 * on missing hmac.
 * Return value: 0 - verification failed, 1 - verification succeded
 */
int FIPSCHECK_verify_files_ex(const char *hmac_suffix, int fail_if_missing, const char *files[]);

/* Checks for presence of the HMAC checksum of the library or binary which
 * contains the symbol.
 * If libname or symbolname is NULL, then the checksum of the executable
 * binary which is being executed is looked up. Non NULL hmac_suffix
 * specifies the file name suffix of the HMAC checksum file.
 * Return value: 0 - checksum not found, 1 - checksum found
 */
int FIPSCHECK_fips_module_installed(const char *libname, const char *symbolname, const char *hmac_suffix);

/*
 * Auxiliary function - returns path pointing to the executable file which is being
 * run. The path buffer must be large enough to hold the path, otherwise it is truncated.
 * Return value: 0 - success -1 - failure
 */
int FIPSCHECK_get_binary_path(char *path, size_t pathlen);

/*
 * Auxiliary function - returns path pointing to the shared library file with a name
 * libname and containing a symbol symbolname. The path buffer must be large enough to
 * hold the path, otherwise it is truncated.
 * Return value: 0 - success -1 - failure
 */
int FIPSCHECK_get_library_path(const char *libname, const char *symbolname, char *path, size_t pathlen);

/*
 * Auxiliary function - returns the value of the kernel fips mode flag.
 * Return value: 0 - the kernel fips mode flag is 0 or unreadable
 * 1 - the kernel fips mode flag is 1
 */
int FIPSCHECK_kernel_fips_mode(void);
