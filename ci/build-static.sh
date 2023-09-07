#!/bin/sh

if [[ -z "${ARCH}" ]]; then
  echo "ARCH is not set to a valid architecture"
  exit 1
fi

make STATIC=1 LDFLAGS=-largp
cp bin/secvarctl secvarctl.${ARCH}