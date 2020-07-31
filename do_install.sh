sudo apt-get update && sudo apt install --yes gnupg2 wget lsb-release
wget -O - https://files.freeswitch.org/repo/deb/debian-release/fsstretch-archive-keyring.asc | apt-key add -
echo "deb http://files.freeswitch.org/repo/deb/debian-release/ `lsb_release -sc` main" > /etc/apt/sources.list.d/freeswitch-stir-deps.list
echo "deb-src http://files.freeswitch.org/repo/deb/debian-release/ `lsb_release -sc` main" >> /etc/apt/sources.list.d/freeswitch-stir-deps.list
sudo apt-get update && sudo apt install --yes automake autoconf libtool libcurl4-openssl-dev libjwt-dev libks

./bootstrap.sh
./configure
make
make check
sudo make install
