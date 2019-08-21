#!/bin/bash
# Run from root source folder ~/qemu/ as follows: ./txscripts/build.sh

mkdir -p build
pushd build
../configure --target-list=aarch64-softmmu --enable-plugins --enable-virtfs
make -j8
popd
pushd plugins/perfsim-log/
make
popd

