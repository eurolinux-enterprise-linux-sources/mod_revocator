Name: mod_revocator
Version: 1.0.3
Release: 1%{?dist}
Summary: CRL retrieval module for the Apache HTTP server
Group: System Environment/Daemons
License: ASL 2.0
URL: http://directory.fedora.redhat.com/wiki/Mod_revocator
Source: http://directory.fedora.redhat.com/sources/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: nspr-devel >= 4.6, nss-devel >= 3.11.9
BuildRequires: nss-pkcs11-devel >= 3.11
BuildRequires: httpd-devel >= 0:2.0.52, apr-devel, apr-util-devel
BuildRequires: pkgconfig, automake
BuildRequires: openldap-devel >= 2.2.29
Requires: mod_nss >= 1.0.8
Patch1: mod_revocator-libpath.patch
Patch2: mod_revocator-kill.patch

%description
The mod_revocator module retrieves and installs remote
Certificate Revocate Lists (CRLs) into an Apache web server. 

%prep
%setup -q
%patch1 -p1
%patch2 -p1

%build
# Needed for ppc64, automake can't be run here
for file in %{_datadir}/automake-*/config.{guess,sub}
do
    cp -f $file .
done

CFLAGS="$RPM_OPT_FLAGS"
export CFLAGS

NSPR_INCLUDE_DIR=`/usr/bin/pkg-config --variable=includedir nspr`
NSPR_LIB_DIR=`/usr/bin/pkg-config --variable=libdir nspr`

NSS_INCLUDE_DIR=`/usr/bin/pkg-config --variable=includedir nss`
NSS_LIB_DIR=`/usr/bin/pkg-config --variable=libdir nss`

NSS_BIN=`/usr/bin/pkg-config --variable=exec_prefix nss`

%configure \
    --with-nss-lib=$NSS_LIB_DIR \
    --with-nss-inc=$NSS_INCLUDE_DIR \
    --with-nspr-lib=$NSPR_LIB_DIR \
    --with-nspr-inc=$NSPR_INCLUDE_DIR \
    --with-apr-config --enable-openldap

make %{?_smp_flags} all

%install
# The install target of the Makefile isn't used because that uses apxs
# which tries to enable the module in the build host httpd instead of in
# the build root.
rm -rf $RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d
mkdir -p $RPM_BUILD_ROOT%{_libdir}/httpd/modules
mkdir -p $RPM_BUILD_ROOT%{_bindir}

install -m 644 revocator.conf $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d/
install -m 755 .libs/libmodrev.so $RPM_BUILD_ROOT%{_libdir}/httpd/modules/mod_rev.so
# Ugh, manually create the ldconfig symbolic links
version=`grep -v '^\#' ./libtool-version`
current=`echo $version | cut -d: -f1`
revision=`echo $version | cut -d: -f2`
age=`echo $version | cut -d: -f3`
install -m  755 .libs/librevocation.so.$current.$revision.$age $RPM_BUILD_ROOT%{_libdir}/
(cd $RPM_BUILD_ROOT%{_libdir} && ln -s librevocation.so.$current.$revision.$age librevocation.so.0)
(cd $RPM_BUILD_ROOT%{_libdir} && ln -s librevocation.so.$current.$revision.$age  librevocation.so)
install -m 755 ldapget $RPM_BUILD_ROOT%{_bindir}/
install -m 755 crlhelper $RPM_BUILD_ROOT%{_bindir}/

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%doc README LICENSE docs/mod_revocator.html
%config(noreplace) %{_sysconfdir}/httpd/conf.d/revocator.conf
%{_libdir}/httpd/modules/mod_rev.so
# rpmlint will complain that librevocation.so is a shared library but this
# must be ignored because this file is loaded directly by name by the Apache
# module.
%{_libdir}/librevocation.*so*
%{_bindir}/ldapget
%{_bindir}/crlhelper

%changelog
* Tue Jan 11 2011 Rob Crittenden <rcritten@redhat.com> - 1.0.3-1
- Update to upstream 1.0.3 (#584103)
- Port forward kill patch from RHEL 5.6

* Wed Dec  5 2007 Rob Crittenden <rcritten@redhat.com> 1.0.2-2
- Respin to pick up new openldap

* Mon Oct 16 2006 Rob Crittenden <rcritten@redhat.com> 1.0.2-1
- Initial build
