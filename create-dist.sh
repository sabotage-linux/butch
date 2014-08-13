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
tempdir_b=$tempdir/butch-$VER
rm -rf $tempdir_b
mkdir -p $tempdir_b

# creating temporary Makefile
cat butch.rcb | rcb2make butch > $tempdir/Makefile
this="$PWD"

cd $tempdir_b
git clone "$librepo" lib
git clone "$butchrepo" butch

for i in `find $tempdir_b/lib -name '*.c'` ; do
	f=$(basename "$i")
	found=0
	for j in `awk '{ if($1 = "DEP:") print $2}' $this/butch.rcb` ; do
		if [ $(basename "$j") = "$f" ] ; then
			found=1
			break;
		fi
	done
	[ $found = 0 ] && rm "$i"
done

mv $tempdir/Makefile $tempdir_b/butch/
cat << EOF > build.sh
#!/bin/sh
make -C butch
EOF
chmod +x build.sh
rm -rf butch/.git
rm -rf butch/sha2/tests
rm -rf lib/.git
cd $tempdir
tar cjf butch-$VER.tar.bz2 butch-$VER
mv butch-$VER.tar.bz2 $me/butch-$VER.tar.bz2
