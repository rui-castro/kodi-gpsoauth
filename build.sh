#!/bin/bash

addon=`grep ".*id=" addon.xml | cut -f2 -d'"'`
dest=build/$addon
version=`grep "^\s\+version" addon.xml | cut -f2 -d'"'`

if [ -d $dest ]; then
    rm -r $dest
fi
mkdir -p $dest

cp addon.xml $dest/
cp icon.png $dest/
cp README.md $dest/
cp -r lib $dest/

if [ -f $dest-$version.zip ]; then
    rm $dest-$version.zip
fi

cd build
zip -r $addon-$version.zip $addon
mv $addon-$version.zip $addon

rm $addon/README.md
rm -r $addon/lib
