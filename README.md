About
-----
Butch is a relatively small and simple package and build manager,
in less than 1000 SLOC of portable C code.

It stands out among other build managers in that it allows to do
more than one thing at once.
in the default configuration, 16 parallel download jobs
(if necessary) and one build job are started, however changing
these numbers just requires overriding them via the env variables
BUTCH_DL_THREADS and BUTCH_BUILD_THREADS.

as soon as one download finished (and the checksum is valid),
the build of the package will be started, unless all build slots
are currently in use, or other dependencies not yet downloaded
or built.

for any job, butch writes a shell script based on a user-supplied
template (see sabotage linux repo for examples)
which is then started and its output redirected into a log file.

It uses a custom, ini-like package format which contains the
following information:
- dependency information (section deps)
- information about a tarball (section vars)
  (can contain source or binaries)
  - filesize
  - sha512 hash
  - tardir, if the tarball doesnt extract to a dir of the same name
  - other variables
- mirror information (section mirrors)
- build section (required to be the last section in the file)
  the contents of the build section are copied verbatim into
  the generated build script.

all sections are optional. it's entirely possible to have
a package that just contains a list of dependencies (a so-called
metapackage), or one that just contains a build section,
or one that just contains a mirror url for a tarball + a main
section containing the metainformation for that tarball.

example package script:

    [deps]
    package-foo
    package-bar
    
    [vars]
    filesize=1024
    sha512=deadbeef
    tardir=foobar-4.2
    
    [mirrors]
    http://foo.bar/foobar-4.2.src.tar.gz
    ftp://ftp.foo.bar/foobar-4.2.src.tar.gz
    http://mirror.qux.bar/foobar-4.2.src.tar.gz
    
    [build]
    ./configure && make && make install

Installation
------------
    cd /tmp
    mkdir butch
    cd butch
    git clone https://github.com/sabotage-linux/butch
    git clone https://github.com/rofl0r/libulz lib
    git clone https://github.com/rofl0r/rcb2
    export PATH=$PATH:/tmp/butch/rcb2
    ln -s /tmp/butch/rcb/rcb2.py /tmp/butch/rcb2/rcb2
    cd butch
    make

