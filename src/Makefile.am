lib_LTLIBRARIES = librevocation.la libmodrev.la

librevocation_la_SOURCES = revocation.cpp crlmanager.cpp rinst.cpp rslot.cpp anchor.cpp constants.c rtoken.cpp rsession.cpp robject.cpp rfind.cpp http-client.cpp ldap-client.cpp exec-client.cpp client.cpp nsprstub.cpp rev_core.cpp revhelper.cpp encode.cpp unescape.cpp 

librevocation_la_LDFLAGS = -version-info `grep -v '^\#' $(srcdir)/libtool-version`
LIB_VERSION = `grep -v '^\#' $(srcdir)/libtool-version | sed 's/:/./g'`

libmodrev_la_SOURCES = mod_rev.c

libmodrev_la_LDFLAGS = -module -avoid-version

INCLUDES = -I@apache_inc@ @nspr_inc@ @nss_inc@ @apr_inc@ -Imozilla/security/nss/lib/base @ldapsdk_inc@ -Imozilla/security/nss/lib/ckfw
LIBS = @ldapsdk_lib@ @nspr_lib@ @nss_lib@ @ldapsdk_libs_ssl@ -lssl3 -lsmime3 -lnss3 -lnssb @ldapsdk_libs@ -lplc4 -lplds4 -lnspr4 -lpthread -ldl
DEFS = -D__REVOCATION_IMPLEMENTATION__=1 @extra_cppflags@

# Remove nsprstub.o from libnssckfw.a so we can use our own stub, then
# relink after the "main" link using the C++ compiler. On Solaris ar
# fails if the object isn't in the library, so be very careful about
# removing it.
all-local: libnssckfw2.a relink ldapget crlhelper

libnssckfw2.a:
	cp @nss_lib_dir@/libnssckfw.a libnssckfw2.a
	files=`ar -t libnssckfw2.a | awk ' /nsprstub.o/ { print } '`; \
	if test X$$files = Xnsprstub.o; then \
	     ar -d libnssckfw2.a nsprstub.o; \
	fi

# The environment variable $CRUNTIME needs to be set to -library=Crun
# on Solaris systems.
relink: librevocation.la libnssckfw2.a
#	rm -f .libs/librevocation.so.$(LIB_VERSION)
#	$(CXX) $(SHARED_LINK) -Wl,-soname,librevocation.so.0 $(am_librevocation_la_OBJECTS) $(LIBS) libnssckfw2.a -lnssb -o .libs/librevocation.so.$(LIB_VERSION) $(CRUNTIME)
	rm -f .libs/librevocation.so*
	$(LIBTOOL) --tag=CXX $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CXXLD) $(AM_CXXFLAGS) \
	$(CXXFLAGS) $(librevocation_la_LDFLAGS) $(LDFLAGS) -o librevocation.la \
	-rpath $(libdir) $(librevocation_la_OBJECTS) $(librevocation_la_LIBADD) $(LIBS) libnssckfw2.a -lnssb

install-exec-local: all-local
	install -m 755 ldapget $(bindir)
	install -m 755 crlhelper $(bindir)

clean-local:
	-rm -f libnssckfw2.a ldapget crlhelper

# Unit test program for fetching data from LDAP URLs. The average user won't
# need to compile or execute this but it is useful enough to keep around.
# This uses the local .libs directory to link against, assuming that the
# revocation library been installed globally yet.
ldaptest:
	$(CXX) $(CXXFLAGS) ldaptest.cpp client.o ldap-client.o unescape.o -o ldaptest $(INCLUDES) $(LIBS) -L .libs/ -lrevocation

# This program is used to retrieve data from an LDAP URL and return the
# attribute data over stdout. It is used in conjunction with an exec:// URL
ldapget: ldapget.cpp relink
	$(CXX) $(CXXFLAGS) ldapget.cpp client.o ldap-client.o http-client.o unescape.o -o ldapget $(INCLUDES) $(LIBS) libnssckfw2.a -L .libs/ -lrevocation

crlhelper: crlhelper.cpp relink
	$(CXX) $(CXXFLAGS) crlhelper.cpp client.o ldap-client.o http-client.o unescape.o -o crlhelper $(INCLUDES) $(LIBS) libnssckfw2.a -L .libs/ -lrevocation
