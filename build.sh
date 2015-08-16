#!/bin/bash

dest=`grep ".*id=" addon.xml | cut -f2 -d'"'`
version=`grep "^\s\+version" addon.xml | cut -f2 -d'"'`

if [ -d $dest ]; then
    rm -r $dest
fi

mkdir $dest
cp addon.xml $dest/
cp icon.png $dest/
cp -r lib $dest/
cp -r platform_libraries $dest/

if [ -f $dest-$version.zip ]; then
    rm $dest-$version.zip
fi

zip -r $dest-$version.zip $dest
rm -r $dest
