#!/bin/sh
if [[ -z "$VER" ]] ; then
	echo set VER!
	exit
fi

librepo=http://github.com/rofl0r/libulz
butchrepo=http://github.com/rofl0r/butch
librepo=~/cdev/cdev/lib
butchrepo=~/cdev/cdev/pkg

# running make once so the .rcb file gets populated
make || exit 1

me=`pwd`
tempdir=/tmp/butch-0000
tempdir_b=$tempdir/butch
rm -rf $tempdir_b
mkdir -p $tempdir_b

# creating temporary Makefile
cat butch.rcb | rcb2make butch > $tempdir/Makefile

cd $tempdir_b
git clone "$librepo" lib
git clone "$butchrepo" butch

mv $tempdir/Makefile $tempdir_b/butch/
cat << EOF > build.sh
#!/bin/sh
cd butch
make -j$MAKE_THREADS
EOF
chmod +x build.sh
rm -rf butch/.git
rm -rf butch/sha2/tests
rm -rf lib/.git
cd $tempdir
tar cjf butch.tar.bz2 butch/
mv butch.tar.bz2 $me/butch-$VER.tar.bz2
