#!/bin/sh

#--------------------------------------------------------------------------------------
# install docker
# https://docs.docker.com/installation/ubuntulinux/

wget -qO- https://get.docker.com/ | sh

#--------------------------------------------------------------------------------------
# set docker network defaults

cat >/etc/default/docker <<'EOL'
DOCKER_OPTS="--dns 8.8.8.8 --dns 8.8.4.4 --ip 127.0.0.1"
EOL

service docker restart