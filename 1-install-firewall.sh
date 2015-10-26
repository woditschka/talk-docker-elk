#!/bin/sh

#--------------------------------------------------------------------------------------
# update system

apt-get -y update
apt-get -y upgrade

#--------------------------------------------------------------------------------------
# install and configure ufw ssh/http

ufw status
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw --force enable
