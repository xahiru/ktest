#!/bin/bash
#This script creates a device for the ktest module.

OUT="ktest.c"
ARG1=".ktest"
ARG2="85"

echo "Building '$OUT' file using /dev/$ARG1 for Device Name and $ARG2 as a Major Number..."
rm -f /dev/$ARG1 #Making sure it's cleared
echo "Creating virtual device /dev/$ARG1"
mknod /dev/$ARG1 c $ARG2 0
chmod 777 /dev/$ARG1

