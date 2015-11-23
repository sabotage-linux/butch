#!/bin/sh
if [ -z "$VER" ] ; then
	echo set VER!
	exit
fi

librepo=http://github.com/rofl0r/libulz
butchrepo=http://github.com/rofl0r/butch
librepo=~/libulz
butchrepo=~/butch

# running make once so the .rcb file gets populated
make || exit 1

me=`pwd`
tempdir=/tmp/butch-0000
tempdir_b=$tempdir/butch-$VER
rm -rf $tempdir_b
mkdir -p $tempdir_b

# creating temporary Makefile
cat butch.rcb | sed 's@[ \t]\.\./@ @g' | ../rcb/rcb2make.pl butch > $tempdir_b/Makefile
this="$PWD"

cd $tempdir_b
git clone "$librepo" libulz
git clone "$butchrepo" butch
for i in butch.c LICENSE README.md ; do
	mv butch/$i .
done
sed -i 's@"../lib/@"libulz/@g' butch.c
rm -rf butch
rm -rf libulz/.git
rm -rf libulz/examples
rm -rf libulz/tests
rm -rf libulz/lib
rm -f libulz/Makefile
rm -f libulz/.gitignore

u=0
uu=0
for i in `find $tempdir_b/libulz -name '*.c'` ; do
	f=$(basename "$i")
	found=0
	for j in `awk '{ if($1 = "DEP:") print $2}' $this/butch.rcb` ; do
		if [ $(basename "$j") = "$f" ] ; then
			u=$(($u + 1))
			found=1
			break;
		fi
	done
	[ $found = 0 ] && { uu=$(($uu + 1)) ; echo rm "$i"; rm "$i" ; }
done
echo "used/unused files from libulz: $u/$uu"

cd $tempdir
tar cjf butch-$VER.tar.bz2 butch-$VER
mv butch-$VER.tar.bz2 $me/butch-$VER.tar.bz2
ls -la $me/butch-$VER.tar.bz2
