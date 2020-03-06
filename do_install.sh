tools="automake autoconf libtool"
libs="libjansson-dev libcjson-dev libcurl-ocaml-dev libjwt-dev"

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
