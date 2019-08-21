strace-process-tree
===================

Reads strace -f output and produces a process tree.  Example ::

    $ strace -f -e trace=process -s 1024 -o /tmp/trace.out make binary-package
    ...

    $ strace-process-tree /tmp/trace.out
    25510 make binary-package
      ├─25511 /bin/sh -c 'dpkg-parsechangelog | awk '\''$1 == "Source:" { print $2 }'\'''
      │   ├─25512 dpkg-parsechangelog
      │   │   └─25514 tail -n 40 debian/changelog
      │   └─25513 awk '$1 == "Source:" { print $2 }'
      ├─25515 /bin/sh -c 'dpkg-parsechangelog | awk '\''$1 == "Version:" { print $2 }'\'''
      │   ├─25516 dpkg-parsechangelog
      │   │   └─25518 tail -n 40 debian/changelog
      │   └─25517 awk '$1 == "Version:" { print $2 }'
      ├─25519 /bin/sh -c 'dpkg-parsechangelog | grep ^Date: | cut -d: -f 2- | date --date="$(cat)" +%Y-%m-%d'
      │   ├─25520 dpkg-parsechangelog
      │   │   └─25525 tail -n 40 debian/changelog
      │   ├─25521 grep ^Date:
      │   ├─25522 cut -d: -f 2-
      │   └─25523 date --date=" Thu, 18 Jan 2018 23:39:51 +0200" +%Y-%m-%d
      │       └─25524 cat
      └─25526 /bin/sh -c 'dpkg-parsechangelog | awk '\''$1 == "Distribution:" { print $2 }'\'''
          ├─25527 dpkg-parsechangelog
          │   └─25529 tail -n 40 debian/changelog
          └─25528 awk '$1 == "Distribution:" { print $2 }'


Installation
------------

Use your favourite pip wrapper to install strace-process-tree, e.g.

    pipx install strace-process-tree


Synopsis
--------

Usage: strace_process_tree.py [-h] [--version] [-v] filename

Read strace -f output and produce a process tree. Recommended strace options
for best results:

  strace -f -e trace=process -s 1024 -o FILENAME COMMAND

positional arguments:
  filename       strace log to parse (use - to read stdin)

optional arguments:
  -h, --help     show this help message and exit
  --version      show program's version number and exit
  -v, --verbose  more verbose output

