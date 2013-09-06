dist_man_MANS = FIPSCHECK_get_binary_path.3 FIPSCHECK_get_library_path.3 FIPSCHECK_kernel_fips_mode.3 \
	FIPSCHECK_verify.3 FIPSCHECK_verify_files.3 FIPSCHECK_verify_ex.3 FIPSCHECK_verify_files_ex.3 \
	FIPSCHECK_fips_module_installed.3 fipscheck.h.3 fipscheck.8 fipshmac.8

manpages_XMLSOURCES = fipscheck.3.xml fipscheck.8.xml fipshmac.8.xml

EXTRA_DIST = $(manpages_XMLSOURCES)

$(dist_man_MANS): $(manpages_XMLSOURCES)
	for i in $^ ; do xmlto man $$i ; done
