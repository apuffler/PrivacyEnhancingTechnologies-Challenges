#!/bin/bash

#COMMAND RESULTING IN TRACKER-ID: minimodem -r -a -q -f sound.flac 9000
for i in {0..1000}
do
echo "$i" >> bruteforce_out.txt
minimodem -r -q -f sound.flac $i >> bruteforce_out.txt
echo "" >> bruteforce_out.txt
done
