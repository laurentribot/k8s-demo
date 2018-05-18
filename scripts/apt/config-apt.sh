#!/usr/bin/env bash

mv /etc/apt/sources.list /etc/apt/sources.list.bak
echo "deb [arch=amd64 trusted=yes] file:///vagrant_data/debs ./" > /etc/apt/sources.list

systemctl stop apt-daily.timer
systemctl disable apt-daily.timer
systemctl mask apt-daily.service
systemctl daemon-reload
killall apt-get
sleep 5
