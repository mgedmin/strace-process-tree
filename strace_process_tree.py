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
import os
import re
import string
import sys
from abc import ABC
from collections import defaultdict
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Set,
    Tuple,
)


if sys.version_info >= (3, 8):
    from typing import Literal  # pragma: nocover
else:
    from typing_extensions import Literal  # pragma: nocover


__version__ = '1.3.1.dev0'
__author__ = 'Marius Gedminas <marius@gedmin.as>'
__url__ = "https://github.com/mgedmin/strace-process-tree"
__licence__ = 'GPL v2 or v3'  # or ask me for MIT


class Tree(NamedTuple):
    trunk: str
    fork: str
    end: str
    space: str


Style = Callable[[Any], str]
Mogrifier = Callable[[str], str]
Pid = int
TimeSeconds = float
SemanticStyle = Literal["tree_style", "pid", "process", "time_range"]
VisualStyle = Literal["normal", "red", "green", "blue"]


def NoopStyle() -> Style:
    # mypy complains that this is used with a non-method but we are creating a method with this.
    @staticmethod  # type: ignore
    def _no_format(text: Any) -> str:
        return text or ''

    return _no_format


ANSI_RESET_CODE = '\033[m'


def AnsiStyle(enter_code: str) -> Style:
    # mypy complains that this is used with a non-method but we are creating a method with this.
    @staticmethod  # type: ignore
    def _format(text: Any) -> str:
        if not text:
            return ''
        return f'{enter_code}{text}{ANSI_RESET_CODE}'

    return _format


class Theme(ABC):
    tree: Tree

    normal = NoopStyle()
    red: Style
    green: Style
    blue: Style

    tree_style: Style
    pid: Style
    process: Style
    time_range: Style

    def __init__(self, tree: Tree, styles: Dict[SemanticStyle, VisualStyle] = {}) -> None:
        self.tree = tree

        # Set up semantic styles
        self.tree_style = getattr(self, styles.get("tree_style", "normal"))
        self.pid = getattr(self, styles.get("pid", "red"))
        self.process = getattr(self, styles.get("process", "green"))
        self.time_range = getattr(self, styles.get("time_range", "blue"))


class PlainTheme(Theme):
    red = NoopStyle()
    green = NoopStyle()
    blue = NoopStyle()


class AnsiTheme(Theme):
    red = AnsiStyle('\033[31m')
    green = AnsiStyle('\033[32m')
    blue = AnsiStyle('\033[34m')


class ThemeFactory:
    ascii_tree = Tree(
        '  | ',
        '  |-',
        '  `-',
        '    ',
    )

    unicode_tree = Tree(
        '  │ ',
        '  ├─',
        '  └─',
        '    ',
    )

    @classmethod
    def create(cls, color: Optional[bool] = None, unicode: Optional[bool] = None) -> Theme:
        if color is None:
            color = cls.should_use_color()

        if unicode is None:
            unicode = cls.can_unicode()

        theme_cls = AnsiTheme if color else PlainTheme
        tree = cls.unicode_tree if unicode else cls.ascii_tree

        return theme_cls(tree)

    @classmethod
    def should_use_color(cls) -> bool:
        return (
            cls.is_terminal()
            and cls.terminal_supports_color()
            and not cls.user_dislikes_color()
        )

    @classmethod
    def is_terminal(cls) -> bool:
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

    @classmethod
    def terminal_supports_color(cls) -> bool:
        return (os.environ.get('TERM') or 'dumb') != 'dumb'

    @classmethod
    def user_dislikes_color(cls) -> bool:
        # https://no-color.org/
        return bool(os.environ.get('NO_COLOR'))

    @classmethod
    def can_unicode(cls) -> bool:
        return getattr(sys.stdout, 'encoding', None) == 'UTF-8'


class Event(NamedTuple):
    pid: Pid
    timestamp: Optional[TimeSeconds]
    event: str


def parse_timestamp(timestamp: str) -> TimeSeconds:
    if ':' in timestamp:
        h, m, s = timestamp.split(':')
        return (float(h) * 60 + float(m)) * 60 + float(s)
    else:
        return float(timestamp)


RESUMED_PREFIX = re.compile(r'<... \w+ resumed> ?')
UNFINISHED_SUFFIX = ' <unfinished ...>'
DURATION_SUFFIX = re.compile(r' <\d+(?:\.\d+)?>$')
PID = re.compile(r'^\[pid +(\d+)\]')
TIMESTAMP = re.compile(r'^\d+(?::\d+:\d+)?(?:\.\d+)?\s+')
IGNORE = re.compile(r'^$|^strace: Process \d+ attached$')


def events(stream: Iterable[str]) -> Iterable[Event]:
    pending: Dict[Pid, Tuple[str, Optional[TimeSeconds]]] = {}
    for n, line in enumerate(stream, 1):
        line = line.strip()
        if line.startswith('[pid'):
            line = PID.sub(r'\1', line)
        pid_str, space, event = line.partition(' ')
        try:
            pid = int(pid_str)
        except ValueError:
            if IGNORE.match(line):
                continue
            raise SystemExit(
                "This does not look like a log file produced by strace -f:\n\n"
                "  %s\n\n"
                "There should've been a PID at the beginning of line %d."
                % (line, n))
        event = event.lstrip()
        timestamp = None
        if event[:1].isdigit():
            m = TIMESTAMP.match(event)
            if m is not None:
                timestamp = parse_timestamp(m.group())
                event = event[m.end():]
        if event.endswith('>'):
            e, sp, d = event.rpartition(' <')
            if DURATION_SUFFIX.match(sp + d):
                event = e
        if event.startswith('<...'):
            m = RESUMED_PREFIX.match(event)
            if m is not None:
                pending_event, timestamp = pending.pop(pid)
                event = pending_event + event[m.end():]
        if event.endswith(UNFINISHED_SUFFIX):
            pending[pid] = (event[:-len(UNFINISHED_SUFFIX)], timestamp)
        else:
            yield Event(pid, timestamp, event)


class Process(NamedTuple):
    pid: Optional[Pid]
    seq: int
    name: Optional[str]
    parent: Optional["Process"]


class ProcessTree:
    processes: Dict[Optional[Pid], Process]
    start_time: Dict[Process, Optional[TimeSeconds]]
    exit_time: Dict[Process, Optional[TimeSeconds]]
    children: Dict[Optional[Process], Set[Process]]

    def __init__(self) -> None:
        self.processes = {}
        self.start_time = {}
        self.exit_time = {}
        self.children = defaultdict(set)
        # Invariant: every Process appears exactly once in
        # self.children[some_parent].

    def add_child(self, ppid: Optional[Pid], pid: Pid, name: str, timestamp: Optional[TimeSeconds]) -> None:
        parent = self.processes.get(ppid)
        if parent is None:
            # This can happen when we attach to a running process and so miss
            # the initial execve() call that would have given it a name.
            parent = Process(pid=ppid, seq=0, name=None, parent=None)
            self.children[None].add(parent)
        # NB: it's possible that strace saw code executing in the child process
        # before the parent's clone() returned a value, so we might already
        # have a self.processes[pid].
        old_process = self.processes.get(pid)
        if old_process is not None:
            self.children[old_process.parent].remove(old_process)
            child = old_process._replace(parent=parent)
        else:
            # We pass seq=0 here and seq=1 in handle_exec() because
            # conceptually clone() happens before execve(), but we must be
            # ready to handle these two events in either order.
            child = Process(pid=pid, seq=0, name=name, parent=parent)
        self.processes[pid] = child
        self.children[parent].add(child)
        # The timestamp of clone() is always going to be earlier than the
        # timestamp of execve() so we use unconditional assignment here but a
        # setdefault() in handle_exec().
        self.start_time[child] = timestamp

    def handle_exec(self, pid: Optional[Pid], name: Optional[str], timestamp: Optional[TimeSeconds]) -> None:
        old_process = self.processes.get(pid)
        if old_process:
            new_process = old_process._replace(seq=old_process.seq + 1,
                                               name=name)
            if old_process.seq == 0 and not self.children[old_process]:
                # Drop the child process if it did nothing interesting between
                # fork() and exec().
                self.children[old_process.parent].remove(old_process)
        else:
            new_process = Process(pid=pid, seq=1, name=name, parent=None)
        self.processes[pid] = new_process
        self.children[new_process.parent].add(new_process)
        self.start_time.setdefault(new_process, timestamp)

    def handle_exit(self, pid: Pid, timestamp: Optional[TimeSeconds]) -> None:
        process = self.processes.get(pid)
        if process:
            # process may be None when we attach to a running process and
            # see it exit before it does any clone()/execve() calls
            self.exit_time[process] = timestamp

    def _format_time_range(self, start_time: Optional[TimeSeconds], exit_time: Optional[TimeSeconds]) -> str:
        if start_time is not None and exit_time is not None:
            return '[{duration:.1f}s @{start_time:.1f}s]'.format(
                start_time=start_time,
                duration=exit_time - start_time
            )
        elif start_time:  # skip both None and 0 please
            return '[@{start_time:.1f}s]'.format(
                start_time=start_time,
            )
        else:
            return ''

    def _format_process_name(self, theme: Theme, name: Optional[str], indent: str, cs: str, ccs: str, padding: str) -> str:
        lines = (name or '').split('\n')
        return '\n{indent}{tree}{padding}'.format(
            indent=indent,
            tree=theme.tree_style(cs + ccs),
            padding=padding,
        ).join(
            theme.process(line)
            for line in lines
        )

    def _format(self, theme: Theme, processes: List[Process], indent: str = '', level: int = 0) -> str:
        r = []
        for n, process in enumerate(processes):
            if level == 0:
                s, cs = '', ''
            elif n < len(processes) - 1:
                s, cs = theme.tree.fork, theme.tree.trunk
            else:
                s, cs = theme.tree.end, theme.tree.space
            children = sorted(self.children[process])
            if children:
                ccs = theme.tree.trunk
            else:
                ccs = theme.tree.space
            time_range = self._format_time_range(
                self.start_time.get(process),
                self.exit_time.get(process),
            )
            title = '{pid} {name} {time_range}'.format(
                pid=theme.pid(process.pid or '<unknown>'),
                name=self._format_process_name(
                    theme, process.name, indent, cs, ccs, theme.tree.space),
                time_range=theme.time_range(time_range),
            ).rstrip()
            r.append(indent + (theme.tree_style(s) + title).rstrip() + '\n')
            r.append(self._format(theme, children, indent+cs, level+1))

        return ''.join(r)

    def format(self, theme: Theme) -> str:
        return self._format(theme, sorted(self.children[None]))

    def __str__(self) -> str:
        return self.format(ThemeFactory.create(unicode=True))


def simplify_syscall(event: str) -> str:
    # clone(child_stack=0x..., flags=FLAGS, parent_tidptr=..., tls=...,
    #       child_tidptr=...) => clone(FLAGS)
    if event.startswith('clone('):
        event = re.sub('[(].*, flags=([^,]*), .*[)]', r'(\1)', event)
    return event.rstrip()


def extract_command_line(event: str) -> str:
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
        argv = parse_argv(command)
        return format_command(argv)
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


def parse_argv(s: str) -> List[str]:
    # '"foo", "bar"..., "baz", "\""' => ['foo', 'bar...', 'baz', '"']
    it = iter(s + ",")
    args = []
    for c in it:
        if c == ' ':
            continue
        assert c == '"', c
        arg = []
        for c in it:  # pragma: no branch -- loop will execute at least once
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


def format_command(command: Iterable[str]) -> str:
    return ' '.join(map(pushquote, (
        arg if all(c in SHELL_SAFE_CHARS for c in arg) else
        '"%s"' % arg if all(c in SHELL_SAFE_QUOTED for c in arg) else
        "'%s'" % arg.replace("'", "'\\''")
        for arg in command
    )))


def pushquote(arg: str) -> str:
    # Change "--foo=bar" to --foo="bar" because that looks better to human eyes
    return re.sub('''^(['"])(--[a-zA-Z0-9_-]+)=''', r'\2=\1', arg)


def parse_stream(event_stream: Iterable[Event], mogrifier: Mogrifier = extract_command_line) -> ProcessTree:
    tree = ProcessTree()
    first_timestamp = None
    for e in event_stream:
        timestamp = e.timestamp
        if timestamp is not None:
            if first_timestamp is None:
                first_timestamp = timestamp
            timestamp -= first_timestamp
        if e.event.startswith('execve('):
            args, equal, result = e.event.rpartition(' = ')
            if result == '0':
                name = mogrifier(args)
                tree.handle_exec(e.pid, name, timestamp)
        if e.event.startswith(('clone(', 'fork(', 'vfork(')):
            args, equal, result = e.event.rpartition(' = ')
            # if clone() fails, the event will look like this:
            #   clone(...) = -1 EPERM (Operation not permitted)
            # and it will fail the result.isdigit() check
            if result.isdigit():
                child_pid = int(result)
                name = mogrifier(args)
                tree.add_child(e.pid, child_pid, name, timestamp)
        if e.event.startswith('+++ exited with '):
            tree.handle_exit(e.pid, timestamp)
    return tree


def main() -> None:
    parser = argparse.ArgumentParser(
        description="""
            Read strace -f output and produce a process tree.

            Recommended strace options for best results:

                strace -f -ttt -e trace=process -s 1024 -o FILENAME COMMAND
            """)
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('-c', '--color', action='store_true', default=None,
                        help='force color output')
    parser.add_argument('-C', '--no-color', action='store_false', dest='color',
                        help='disable color output')
    parser.add_argument('-U', '--unicode', action='store_true', default=None,
                        help='force Unicode output')
    parser.add_argument('-A', '--ascii', action='store_false', dest='unicode',
                        help='force ASCII output')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='more verbose output')
    parser.add_argument('filename', type=argparse.FileType('r'),
                        help='strace log to parse (use - to read stdin)')
    args = parser.parse_args()

    mogrifier = simplify_syscall if args.verbose else extract_command_line

    tree = parse_stream(events(args.filename), mogrifier)

    theme = ThemeFactory.create(color=args.color, unicode=args.unicode)
    print(tree.format(theme).rstrip())


if __name__ == '__main__':
    main()
