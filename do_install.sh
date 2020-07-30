tools="automake autoconf libtool"
libs="libjansson-dev libcurl-ocaml-dev libjwt-dev libks"

sudo apt install --yes $tools
sudo apt install --yes $libs

autoreconf -i
automake --add-missing
libtoolize
autoreconf
./configure
make && sudo make install
make stirshaken
make check
