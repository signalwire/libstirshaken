COMPILATION

May need to export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib if CJSON is in folder that is not currently in LD_LIBRARY_PATH.

autoreconf
automake --add-missing
libtoolize
autoreconf

