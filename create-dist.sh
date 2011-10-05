#!/bin/sh
if [[ -z "$VER" ]] ; then
	echo set VER!
	exit
fi
me=`pwd`
tempdir=/tmp/butch-0000
tempdir_b=$tempdir/butch
rm -rf $tempdir_b
mkdir -p $tempdir_b
cd $tempdir_b
git clone http://github.com/rofl0r/libulz lib
git clone http://github.com/rofl0r/butch
cat << EOF > build.sh
#!/bin/sh
cd lib
make
mv lib/libulz.a ../butch
cd ../butch
if [ -z "\$CC" ] ; then
	CC=cc
fi
\$CC -Wall -Wextra -g -O0 butch.c sha2/sha512.c sha2/sha2_variables.c -o butch -L. -lulz
EOF
chmod +x build.sh
rm -rf butch/.git
rm -rf butch/sha2/tests
rm -rf lib/.git
cd $tempdir
tar cjf butch.tar.bz2 butch/
mv butch.tar.bz2 $me/butch-$VER.tar.bz2
