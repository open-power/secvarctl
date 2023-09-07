#!/bin/bash

RPMBUILD_ROOT=$(rpmbuild -E %_topdir)

# Get version for rpmbuild tarball generation
# Ignore the extra version string, it's not needed for tarball generation
source VERSION
SECVARCTL_VERSION=${SECVARCTL_VERSION%${SECVARCTL_VERSION_EXTRA}}

set -e

# Generate source tarball
ln -s . secvarctl-${SECVARCTL_VERSION}
tar czf secvarctl-${SECVARCTL_VERSION}.tar.gz secvarctl-${SECVARCTL_VERSION}/*
mkdir -p ${RPMBUILD_ROOT}/SOURCES
cp secvarctl-${SECVARCTL_VERSION}.tar.gz ${RPMBUILD_ROOT}/SOURCES

# Run Build
if [[ "x86_64" == $(uname -m) ]]; then
  # Only one srpm is needed, so just arbitrarily pick the faster x86_64 build to do it
  rpmbuild -ba secvarctl.spec
else
  rpmbuild -bb secvarctl.spec
fi

# Move generated RPMs out of container
mkdir -p rpms
cp ${RPMBUILD_ROOT}/RPMS/*/*.rpm rpms/
if [[ "x86_64" == $(uname -m) ]]; then
  # Only the x86_64 build generates the srpm, same for all arches
  cp ${RPMBUILD_ROOT}/SRPMS/*.rpm rpms/
fi

# SUSE rpms don't appear to insert a distro tag, so invent one
source /etc/os-release

function rename_rpm {
  cd rpms/
  for rpm in *.rpm; do
    # This feels kind of fragile, if this ever breaks it should be updated
    NEW="$(echo $rpm | cut -d . -f -2).$1.$(echo $rpm | cut -d . -f 3-)"
    mv $rpm $NEW
  done
  cd -
}

case $ID in
  opensuse-tumbleweed)
    rename_rpm stw
  ;;

  opensuse-leap)
    rename_rpm "s$(echo $VERSION | cut -d . -f 1)"
  ;;

esac