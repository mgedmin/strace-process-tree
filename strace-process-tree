#!/usr/bin/python3
# -*- coding: UTF-8 -*-
"""
Usage:
  strace-process-tree filename

Read strace -f output and produce a process tree.

Recommended strace options for best results:

    strace -f -e trace=process -s 1024 -o filename.out command args

"""

import argparse
import re
import string
from collections import defaultdict, namedtuple


__version__ = '0.9.0'
__author__ = 'Marius Gedminas <marius@gedmin.as>'
__url__ = "https://github.com/mgedmin/scripts/blob/master/strace-process-tree"
__licence__ = 'GPL v2 or later'  # or ask me for MIT


def events(stream):
    RESUMED_PREFIX = re.compile(r'<... \w+ resumed> ')
    UNFINISHED_SUFFIX = ' <unfinished ...>'
    DURATION_SUFFIX = re.compile(r' <\d+([.]\d+)?>$')
    PID = re.compile(r'^\[pid (\d+)\]')
    TIMESTAMP = re.compile(r'^(\d+|\d+:\d+:\d+)([.]\d+)?\s+')
    IGNORE = re.compile(r'^$|^strace: Process \d+ attached$')
    pending = {}
    for line in stream:
        line = PID.sub(r'\1', line.rstrip())
        pid, space, event = line.partition(' ')
        try:
            pid = int(pid)
        except ValueError:
            if IGNORE.match(line):
                continue
            raise SystemExit(
                "This does not look like a log file produced by strace -f:\n\n"
                "  %s\n\n"
                "There should've been a PID at the beginning of the line."
                % line)
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


Process = namedtuple('Process', 'pid, seq, name, parent')


class ProcessTree(object):
    def __init__(self):
        self.processes = {}
        self.children = defaultdict(set)
        # Invariant: every Process appears exactly once in
        # self.children[some_parent].

    def add_child(self, ppid, pid, name):
        parent = self.processes.get(ppid)
        if parent is None:
            parent = Process(ppid, 1, None, None)
            self.children[None].add(parent)
        child = self.processes.setdefault(pid, Process(pid, 0, name, parent))
        self.children[parent].add(child)

    def handle_exec(self, pid, name):
        old_process = self.processes.get(pid)
        if old_process:
            new_process = Process(pid, old_process.seq + 1, name,
                                  old_process.parent)
            if old_process.seq == 0 and not self.children[old_process]:
                # Drop the child process if it did nothing interesting between
                # fork() and exec().
                self.children[old_process.parent].remove(old_process)
        else:
            new_process = Process(pid, 1, name, None)
        self.processes[pid] = new_process
        self.children[new_process.parent].add(new_process)

    def _format(self, processes, indent='', level=0):
        r = []
        for n, process in enumerate(processes):
            if level == 0:
                s, cs = '', ''
            elif n < len(processes) - 1:
                s, cs = '  ├─', '  │ '
            else:
                s, cs = '  └─', '    '
            name = process.name or ''
            children = sorted(self.children[process])
            if children:
                ccs = '  │ '
            else:
                ccs = '    '
            name = name.replace('\n', '\n' + indent + cs + ccs + '    ')
            r.append(indent + s + '{} {}\n'.format(process.pid, name))
            r.append(self._format(children, indent+cs, level+1))

        return ''.join(r)

    def format(self):
        return self._format(sorted(self.children[None]))

    def __str__(self):
        return self.format()


def simplify_syscall(event):
    # clone(child_stack=0x..., flags=FLAGS, parent_tidptr=..., tls=...,
    #       child_tidptr=...) => clone(FLAGS)
    if event.startswith('clone('):
        event = re.sub('[(].*, flags=([^,]*), .*[)]', r'(\1)', event)
    return event.rstrip()


def extract_command_line(event):
    # execve("/usr/bin/foo", ["foo", "bar"], [/* 45 vars */]) => foo bar
    if event.startswith('clone('):
        if 'CLONE_THREAD' in event:
            return '(thread)'
        elif 'flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD' in event:
            return '(fork)'
        else:
            return '...'
    elif event.startswith('execve('):
        command = event.strip()
        command = re.sub(r'^execve\([^[]*\[', '', command)
        command = re.sub(r'\], (0x[0-9a-f]+ )?\[?/\* \d+ vars \*/\]?\)$', '',
                         command)
        command = parse_argv(command)
        return format_command(command)
    else:
        return event.rstrip()


ESCAPES = {
    'n': '\n',
    'r': '\r',
    't': '\t',
    'b': '\b',
    '0': '\0',
    'a': '\a',
}


def parse_argv(s):
    # '"foo", "bar"..., "baz", "\""' => ['foo', 'bar...', 'baz', '"']
    it = iter(s + ",")
    args = []
    for c in it:
        if c == ' ':
            continue
        assert c == '"', c
        arg = []
        for c in it:
            if c == '"':
                break
            if c == '\\':
                c = next(it)
                arg.append(ESCAPES.get(c, c))
            else:
                arg.append(c)
        c = next(it)
        if c == ".":
            arg.append('...')
            c = next(it)
            assert c == ".", c
            c = next(it)
            assert c == ".", c
            c = next(it)
        args.append(''.join(arg))
        assert c == ',', (c, s)
    return args


SHELL_SAFE_CHARS = set(string.ascii_letters + string.digits + '%+,-./:=@^_~')
SHELL_SAFE_QUOTED = SHELL_SAFE_CHARS | set("!#&'()*;<>?[]{|} \t\n")


def format_command(command):
    return ' '.join(map(pushquote, (
        arg if all(c in SHELL_SAFE_CHARS for c in arg) else
        '"%s"' % arg if all(c in SHELL_SAFE_QUOTED for c in arg) else
        "'%s'" % arg.replace("'", "'\\''")
        for arg in command
    )))


def pushquote(arg):
    # Change "--foo=bar" to --foo="bar" because that looks better to human eyes
    return re.sub('''^(['"])(--[a-zA-Z0-9_-]+)=''', r'\2=\1', arg)


def main():
    parser = argparse.ArgumentParser(
        description="""
            Read strace -f output and produce a process tree.

            Recommended strace options for best results:

                strace -f -e trace=process -s 1024 -o FILENAME COMMAND
            """)
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='more verbose output')
    parser.add_argument('filename', type=argparse.FileType('r'),
                        help='strace log to parse (use - to read stdin)')
    args = parser.parse_args()

    tree = ProcessTree()

    mogrifier = simplify_syscall if args.verbose else extract_command_line

    for pid, event in events(args.filename):
        if event.startswith('execve('):
            args, equal, result = event.rpartition(' = ')
            if result == '0':
                name = mogrifier(args)
                tree.handle_exec(pid, name)
        if event.startswith(('clone(', 'fork(', 'vfork(')):
            args, equal, result = event.rpartition(' = ')
            if result.isdigit():
                child_pid = int(result)
                name = mogrifier(args)
                tree.add_child(pid, child_pid, name)

    print(tree.format().rstrip())


if __name__ == '__main__':
    main()
