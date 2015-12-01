#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
Usage:
  strace-process-tree [filename]

Read strace -f output and produce a process tree.

Recommended strace options for best results:

    strace -f -e trace=process -s 1024 -o filename.out command args

"""

import re
import fileinput
from collections import defaultdict


__version__ = '0.5.0'
__author__ = 'Marius Gedminas <marius@gedmin.as>'
__url__ = 'https://gist.github.com/mgedmin/4953427'
__licence__ = 'GPL v2 or later' # or ask me for MIT


def events(stream):
    RESUMED_PREFIX = re.compile('<... \w+ resumed> ')
    UNFINISHED_SUFFIX = ' <unfinished ...>'
    DURATION_SUFFIX = re.compile(' <\d+([.]\d+)?>$')
    TIMESTAMP = re.compile('^\d+([.]\d+)?\s+')
    pending = {}
    for line in stream:
        pid, spaces, event = line.rstrip().partition(' ')
        pid = int(pid)
        event = event.lstrip()
        event = TIMESTAMP.sub('', event)
        event = DURATION_SUFFIX.sub('', event)
        m = RESUMED_PREFIX.match(event)
        if m is not None:
            event = pending.pop(pid) + event[len(m.group()):]
        if event.endswith(UNFINISHED_SUFFIX):
            pending[pid] = event[:-len(UNFINISHED_SUFFIX)]
        else:
            yield (pid, event)


class ProcessTree:
    def __init__(self):
        self.names = {}
        self.parents = {}
        self.children = defaultdict(list)
        self.roots = set()
        self.all = set()
        # invariant: self.roots == self.all - set(self.parents), probably

    def make_known(self, pid):
        if pid not in self.all:
            self.roots.add(pid)
            self.all.add(pid)

    def set_name(self, pid, name):
        self.make_known(pid)
        self.names[pid] = name

    def add_child(self, ppid, pid):
        self.make_known(ppid)
        self.make_known(pid)
        if pid in self.roots:
            self.roots.remove(pid)
        self.parents[pid] = ppid
        self.children[ppid].append(pid)

    def _format(self, pids, indent='', level=0):
        r = []
        for n, pid in enumerate(pids):
            if level == 0:
                s, cs = '', ''
            elif n < len(pids) - 1:
                s, cs = '  ├─', '  │ '
            else:
                s, cs = '  └─', '    '
            r.append(indent + s + '{} {}\n'.format(pid, self.names.get(pid, '')))
            r.append(self._format(sorted(self.children.get(pid, [])),
                                  indent+cs, level+1))

        return ''.join(r)

    def __str__(self):
        return self._format(sorted(self.roots))


def simplify_syscall(event):
    # clone(child_stack=0x..., flags=FLAGS, parent_tidptr=..., tls=..., child_tidptr=...) => clone(FLAGS)
    if event.startswith('clone('):
        event = re.sub('[(].*, flags=([^,]*), .*[)]', r'(\1)', event)
    return event


def main():
    tree = ProcessTree()

    for pid, event in events(fileinput.input()):
        if event.startswith('execve('):
            args, equal, result = event.rpartition(' = ')
            if result == '0':
                name = simplify_syscall(args)
                tree.set_name(pid, name)
        if event.startswith(('clone(', 'fork(', 'vfork(')):
            args, equal, result = event.rpartition(' = ')
            if result.isdigit():
                child_pid = int(result)
                name = simplify_syscall(args)
                tree.set_name(child_pid, name)
                tree.add_child(pid, child_pid)

    print(str(tree).rstrip())

if __name__ == '__main__':
    main()
