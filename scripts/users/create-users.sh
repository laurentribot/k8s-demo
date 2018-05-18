#!/usr/bin/env bash

adduser --quiet --disabled-password --gecos "" ansible
echo ansible:ansible | chpasswd

echo "ansible ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/ansible

mkdir ~ansible/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDL0iA1g5PqdLUNxIPc7wBY/53EdYdifIr4UiGiaq8ZxkRfiP66iozpxxYYoVhO0Ck2OKZtzsVTqmejdOtx1seFWqUdopCvwwLYteANC5NWclZIT7/ArPQiUd3+C10kFiznc9iq8HYA7Irx2vczeKgTCjmYpIxcADWBaiUwh9WGN3M7k5aKqJFwFoAxPvuo3xCNJUybYJgxypKYz/zabcqrWKsIWDDEadTAUNiU/sdalhjrkS0ikjiq4Icxc3aUO9NeFoUIHn/BhBsxDsfNcvsGGCy+82YGZJa8A2l4v9ttIPvhJ44PqbXZa03T17GeWZRK5002XiphbS2Gtn1eToQV ansible@" > ~ansible/.ssh/authorized_keys

chown -R ansible:ansible ~ansible/.ssh
chmod 700 ~ansible/.ssh
