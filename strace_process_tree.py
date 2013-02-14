#!/usr/bin/python
"""
Usage:
  strace-process-tree [filename]

Read strace -f output and produce a process tree.
"""

import re
import fileinput
from collections import defaultdict


def events(stream):
    RESUMED_PREFIX = re.compile('<... \w+ resumed> ')
    UNFINISHED_SUFFIX = ' <unfinished ...>'
    pending = {}
    for line in stream:
        pid, spaces, event = line.rstrip().partition('  ')
        pid = int(pid)
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

    def _format(self, pids, indent=''):
        r = []
        for pid in pids:
            r.append(indent + '{} {}\n'.format(pid, self.names.get(pid, '')))
            r.append(self._format(sorted(self.children.get(pid, [])),
                                  indent+'  '))

        return ''.join(r)

    def __str__(self):
        return self._format(sorted(self.roots))


def main():
    tree = ProcessTree()

    for pid, event in events(fileinput.input()):
        if event.startswith('execve('):
            args, equal, result = event.rpartition(' = ')
            if result == '0':
                tree.set_name(pid, args)
        if event.startswith('clone('):
            args, equal, result = event.rpartition(' = ')
            if result.isdigit():
                child_pid = int(result)
                tree.set_name(child_pid, args)
                tree.add_child(pid, child_pid)

    print(tree)

if __name__ == '__main__':
    main()
