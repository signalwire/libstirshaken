autoreconf -i
automake --add-missing
libtoolize
autoreconf
./configure
make
sudo make install
