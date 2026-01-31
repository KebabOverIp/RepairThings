#!/bin/bash
SOURCE=$1
DEST=$2

SRC_GROUPS=$(id -Gn ${SOURCE} | sed "s/ /,/g" | sed -r 's/\<'${SOURCE}'\>\b,?//g')
SRC_SHELL=$(awk -F : -v name=${SOURCE} '(name == $1) { print $7 }' /etc/passwd)

sudo useradd --groups ${SRC_GROUPS} --shell ${SRC_SHELL} --create-home ${DEST}
sudo passwd ${DEST}
