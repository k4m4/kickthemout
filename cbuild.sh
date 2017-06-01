#!/bin/bash
#Copyright Loïc Branstett 2017 MIT License

if ! [ -x "$(command -v cython2)" ]; then
  echo 'Cython2 is not installed.' >&2
  exit 1
fi

if ! [ -x "$(command -v gcc)" ]; then
  echo 'Gcc is not installed.' >&2
  exit 1
fi

echo "Making the C file ...";
cython2 --embed kickthemout.py

echo "Compling C file to executable ..."
gcc $CFLAGS -I/usr/include/python2.7 -o kickthemout kickthemout.c -lpython2.7 -lpthread -lm -lutil -ldl
echo "Compile finish ! You can launch kickthemout with ./kickthemout"
