set -x

rm -r autom4te.cache/
rm l2switch/l2switch
rm aclocal.m4
rm compile
rm config.h
rm config.h.in~
rm config.log
rm config.status
rm configure
rm depcomp
rm install-sh
rm missing
rm stamp-h1

find -name 'Makefile' | xargs rm
find -name 'Makefile.in' | xargs rm
find -name '*.o' | xargs rm
find -name '*.a' | xargs rm
find -name '.deps/' | xargs rm -r

