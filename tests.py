# -*- coding: utf-8 -*-
import os
import sys

import strace_process_tree as stp

import pytest


class FakeStdout:
    def isatty(self):
        return True


def test_Theme_is_terminal_no_it_is_not(capsys):
    assert not stp.Theme.is_terminal()


def test_Theme_is_terminal_yes_it_is(monkeypatch):
    monkeypatch.setattr(sys, 'stdout', FakeStdout())
    assert stp.Theme.is_terminal()


def test_Theme_terminal_supports_color_no(monkeypatch):
    monkeypatch.setitem(os.environ, 'TERM', 'dumb')
    assert not stp.Theme.terminal_supports_color()


def test_Theme_terminal_supports_color_yes(monkeypatch):
    monkeypatch.setitem(os.environ, 'TERM', 'xterm')
    assert stp.Theme.terminal_supports_color()


def test_Theme_autodetection_color_yes(monkeypatch):
    monkeypatch.setattr(sys, 'stdout', FakeStdout())
    monkeypatch.setitem(os.environ, 'TERM', 'xterm')
    assert isinstance(stp.Theme(), stp.AnsiTheme)


def test_Theme_autodetection_color_no(monkeypatch):
    monkeypatch.setattr(sys, 'stdout', FakeStdout())
    monkeypatch.setitem(os.environ, 'TERM', 'dumb')
    assert isinstance(stp.Theme(), stp.PlainTheme)


def test_PlainTheme_bad_style():
    with pytest.raises(AttributeError):
        stp.PlainTheme().waterfall("oOoOoO")


def test_AnsiTheme_bad_style():
    with pytest.raises(AttributeError):
        stp.AnsiTheme().waterfall("oOoOoO")


def test_AnsiTheme_good_style():
    theme = stp.AnsiTheme()
    assert theme.pid('PID') == '\033[31mPID\033[m'


def test_AnsiTheme_empty_text():
    theme = stp.AnsiTheme()
    assert theme.pid('') == ''


@pytest.mark.parametrize(['value', 'expected'], [
    ('123', 123),
    ('123.045', 123.045),
    ('01:02:03', 3723),
    ('01:02:03.045', 3723.045),
])
def test_parse_timestamp(value, expected):
    assert stp.parse_timestamp(value) == expected


def test_events():
    # events() does several things:
    # - extracts the pid if present
    # - extracts timestamps if present
    # - extracts the system call
    # - strips durations if present
    # - assembles system calls split across several lines with <unfinished...> <... resumed>
    log_lines = [
        'strace: Process 27369 attached',
        '27369 13:53:26.881056 execve("bin/test", ["bin/test", "-pvc", "-t", "allowhosts.txt"], 0x7fffa04e8ba0 /* 71 vars */) = 0 <0.000832>',
        '27369 13:53:26.884089 arch_prctl(ARCH_SET_FS, 0x7fbb38e89740) = 0 <0.000008>',
        '27369 13:53:27.213383 clone( <unfinished ...>',
        '27370 13:53:27.214709 execve("/bin/sh", ["sh", "-c", "uname -p 2> /dev/null"], 0x55842eb789e0 /* 72 vars */ <unfinished ...>',
        '27369 13:53:27.214872 <... clone resumed> child_stack=0x7fbb371faff0, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 27370 <0.001466>',
        '27370 13:53:27.214899 <... execve resumed> ) = 0 <0.000132>',
        '27370 13:53:27.216357 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=27371, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---',
        '27370 13:53:27.216395 exit_group(0)     = ?',
        '27370 13:53:27.216441 +++ exited with 0 +++',
    ]
    result = list(stp.events(log_lines))
    assert result == [
        (27369, 50006.881056, 'execve("bin/test", ["bin/test", "-pvc", "-t", "allowhosts.txt"], 0x7fffa04e8ba0 /* 71 vars */) = 0'),
        (27369, 50006.884089, 'arch_prctl(ARCH_SET_FS, 0x7fbb38e89740) = 0'),
        (27369, 50007.213383, 'clone(child_stack=0x7fbb371faff0, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 27370'),
        (27370, 50007.214709, 'execve("/bin/sh", ["sh", "-c", "uname -p 2> /dev/null"], 0x55842eb789e0 /* 72 vars */) = 0'),
        (27370, 50007.216357, '--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=27371, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---'),
        (27370, 50007.216395, 'exit_group(0)     = ?'),
        (27370, 50007.216441, '+++ exited with 0 +++'),
    ]


def test_events_bad_file_format():
    log_lines = [
        'Hello this is a text file and not an strace log file at all actually.',
    ]
    with pytest.raises(SystemExit):
        list(stp.events(log_lines))


def test_ProcessTree():
    pt = stp.ProcessTree()
    pt.handle_exec(42, 'foo', None)
    assert str(pt) == '42 foo\n'


def test_ProcessTree_simple_child():
    pt = stp.ProcessTree()
    pt.handle_exec(42, 'foo', None)
    pt.add_child(42, 43, 'bar', None)
    pt.add_child(42, 44, 'baz', None)
    assert str(pt) == (
        '42 foo\n'
        '  ├─43 bar\n'
        '  └─44 baz\n'
    )


def test_ProcessTree_fork_then_exec():
    pt = stp.ProcessTree()
    pt.handle_exec(42, 'foo', None)
    pt.add_child(42, 43, 'fork()', None)
    pt.handle_exec(43, 'bar', None)
    assert str(pt) == (
        '42 foo\n'
        '  └─43 bar\n'
    )


def test_ProcessTree_exec_then_fork():
    pt = stp.ProcessTree()
    pt.handle_exec(42, 'foo', None)
    pt.handle_exec(43, 'bar', None)
    pt.add_child(42, 43, 'fork()', None)
    assert str(pt) == (
        '42 foo\n'
        '  └─43 bar\n'
    )


def test_ProcessTree_unknown_parent_pid_and_name():
    pt = stp.ProcessTree()
    pt.add_child(None, 43, 'bar', None)
    pt.add_child(None, 44, 'baz', None)
    assert str(pt) == (
        '<unknown>\n'
        '  ├─43 bar\n'
        '  └─44 baz\n'
    )


def test_ProcessTree_unknown_parent_pid():
    pt = stp.ProcessTree()
    pt.handle_exec(None, 'foo', None)
    pt.add_child(None, 43, 'bar', None)
    pt.add_child(None, 44, 'baz', None)
    assert str(pt) == (
        '<unknown> foo\n'
        '  ├─43 bar\n'
        '  └─44 baz\n'
    )


def test_ProcessTree_exec_twice():
    pt = stp.ProcessTree()
    pt.handle_exec(42, 'foo', None)
    pt.add_child(42, 43, 'bar', None)
    pt.handle_exec(43, 'qux', None)
    assert str(pt) == (
        '42 foo\n'
        '  └─43 qux\n'
    )


def test_ProcessTree_exec_twice_with_children():
    pt = stp.ProcessTree()
    pt.handle_exec(42, 'foo', None)
    pt.add_child(42, 43, 'bar', None)
    pt.add_child(43, 44, 'baz', None)
    pt.handle_exec(43, 'qux', None)
    assert str(pt) == (
        '42 foo\n'
        '  ├─43 bar\n'
        '  │   └─44 baz\n'
        '  └─43 qux\n'
    )


def test_ProcessTree_start_time_known_exit_time_not_known():
    pt = stp.ProcessTree()
    pt.handle_exec(42, 'foo', None)
    pt.add_child(42, 43, 'bar', 24)
    assert str(pt) == (
        '42 foo\n'
        '  └─43 bar [@24.0s]\n'
    )


def test_ProcessTree_handle_exit_unknown_pid():
    pt = stp.ProcessTree()
    pt.handle_exit(42, 1775.45)


def test_simplify_syscall():
    assert stp.simplify_syscall(
        'exit_group(0)    '
    ) == (
        'exit_group(0)'
    )
    assert stp.simplify_syscall(
        'clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fbb38e89a10)'
    ) == (
        'clone(CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD)'
    )
    assert stp.simplify_syscall(
        'clone(child_stack=0x7fbb3690dfb0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7fbb3690e9d0, tls=0x7fbb3690e700, child_tidptr=0x7fbb3690e9d0)'
    ) == (
        'clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID)'
    )


def test_extract_command_line():
    assert stp.extract_command_line(
        'exit_group(0)    '
    ) == (
        'exit_group(0)'
    )
    assert stp.extract_command_line(
        'execve("/usr/bin/foo", ["foo", "bar"], [/* 45 vars */])'
    ) == (
        'foo bar'
    )
    assert stp.extract_command_line(
        'clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fbb38e89a10)'
    ) == (
        '(fork)'
    )
    assert stp.extract_command_line(
        'clone(child_stack=0x7fbb3690dfb0, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tidptr=0x7fbb3690e9d0, tls=0x7fbb3690e700, child_tidptr=0x7fbb3690e9d0)'
    ) == (
        '(thread)'
    )
    assert stp.extract_command_line(
        'clone(...)'
    ) == (
        '...'
    )


def test_parse_argv():
    assert stp.parse_argv('"foo"') == ["foo"]
    assert stp.parse_argv('"foo", "bar"') == ["foo", "bar"]
    assert stp.parse_argv(r'"foo", "bar"..., "baz\t", "\""') == [
        "foo", "bar...", "baz\t", '"',
    ]


def test_format_command():
    assert stp.format_command(["foo", "bar"]) == "foo bar"
    assert stp.format_command(["foo", "bar baz"]) == 'foo "bar baz"'
    assert stp.format_command(["foo", "bar`baz's"]) == r"foo 'bar`baz'\''s'"


def test_pushquote():
    assert stp.pushquote('"--foo=bar"') == '--foo="bar"'


def test_parse_stream():
    tree = stp.parse_stream([
        stp.Event(42, 1262372451.579, 'execve("/tmp/test.sh", ["/tmp/test.sh"], 0x7ffc5be66b48 /* 71 vars */) = 0'),
        stp.Event(42, 1262372451.975, 'clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fea1237a850) = 43'),
        stp.Event(43, 1262372452.001, 'execve("/usr/bin/printf", ["/usr/bin/printf", "hi"], 0x557884c640a8 /* 71 vars */) = 0'),
        stp.Event(43, 1262372452.073, 'exit_group(0)                     = ?'),
        stp.Event(43, 1262372452.074, '+++ exited with 0 +++'),
    ])
    assert str(tree) == (
        "42 /tmp/test.sh\n"
        "  └─43 /usr/bin/printf hi [0.1s @0.4s]\n"
    )


def test_parse_stream_exec_error():
    tree = stp.parse_stream([
        stp.Event(42, 1262372451.579, 'execve("/tmp/test.sh", ["/tmp/test.sh"], 0x7ffc5be66b48 /* 71 vars */) = 0'),
        stp.Event(42, 1262372451.975, 'clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fea1237a850) = 43'),
        stp.Event(43, 1262372452.001, 'execve("/usr/bin/printf", ["/usr/bin/printf", "hi"], 0x557884c640a8 /* 71 vars */) = -1 ENOENT (No such file or directory)'),
    ])
    assert str(tree) == (
        "42 /tmp/test.sh\n"
        "  └─43 (fork) [@0.4s]\n"
    )


def test_parse_stream_clone_error():
    tree = stp.parse_stream([
        stp.Event(42, 1262372451.579, 'execve("/tmp/test.sh", ["/tmp/test.sh"], 0x7ffc5be66b48 /* 71 vars */) = 0'),
        stp.Event(42, 1262372451.975, 'clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fea1237a850) = -1 EPERM (Operation not permitted)'),
    ])
    assert str(tree) == (
        "42 /tmp/test.sh\n"
    )


def test_main_no_args(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['strace-process-tree'])
    with pytest.raises(SystemExit):
        stp.main()
    output = capsys.readouterr().err
    assert output.startswith(
        'usage: strace-process-tree [-h] [--version] [-c] [--no-color] [-v] filename\n'
        'strace-process-tree: error:'
    )


def test_main_help(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['strace-process-tree', '--help'])
    with pytest.raises(SystemExit):
        stp.main()
    output = capsys.readouterr().out
    assert output.startswith(
        'usage: strace-process-tree'
    )


def test_main(monkeypatch, tmp_path, capsys):
    filename = tmp_path / "example.log"
    filename.write_text(
        u'29900 execve("/tmp/test.sh", ["/tmp/test.sh"], 0x7ffc5be66b48 /* 71 vars */) = 0\n'
        u'29900 arch_prctl(ARCH_SET_FS, 0x7fea1237a580) = 0\n'
        u'29900 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fea1237a850) = 29901\n'
        u'29900 wait4(-1,  <unfinished ...>\n'
        u'29901 execve("/usr/bin/printf", ["/usr/bin/printf", "hi\\\\n"], 0x557884c640a8 /* 71 vars */) = 0\n'
        u'29901 arch_prctl(ARCH_SET_FS, 0x7f52d9e64580) = 0\n'
        u'29901 exit_group(0)                     = ?\n'
        u'29901 +++ exited with 0 +++\n'
        u'29900 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 29901\n'
        u'29900 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=29901, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---\n'
        u'29900 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fea1237a850) = 29902\n'
        u'29900 wait4(-1,  <unfinished ...>\n'
        u'29902 execve("/tmp/child.sh", ["/tmp/child.sh"], 0x557884c640a8 /* 71 vars */) = 0\n'
        u'29902 arch_prctl(ARCH_SET_FS, 0x7f3125dd8580) = 0\n'
        u'29902 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3125dd8850) = 29903\n'
        u'29902 wait4(-1,  <unfinished ...>\n'
        u'29903 execve("/usr/bin/printf", ["/usr/bin/printf", "one\\\\n"], 0x560fc7c870a8 /* 71 vars */) = 0\n'
        u'29903 arch_prctl(ARCH_SET_FS, 0x7f1cc7344580) = 0\n'
        u'29903 exit_group(0)                     = ?\n'
        u'29903 +++ exited with 0 +++\n'
        u'29902 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 29903\n'
        u'29902 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=29903, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---\n'
        u'29902 execve("/tmp/another.sh", ["/tmp/another.sh"], 0x560fc7c870d8 /* 71 vars */) = 0\n'
        u'29902 arch_prctl(ARCH_SET_FS, 0x7fb887202580) = 0\n'
        u'29902 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fb887202850) = 29904\n'
        u'29902 wait4(-1,  <unfinished ...>\n'
        u'29904 execve("/bin/true", ["/bin/true"], 0x563a7aa1d0a8 /* 71 vars */) = 0\n'
        u'29904 arch_prctl(ARCH_SET_FS, 0x7f2242adc580) = 0\n'
        u'29904 exit_group(0)                     = ?\n'
        u'29904 +++ exited with 0 +++\n'
        u'29902 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 29904\n'
        u'29902 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=29904, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---\n'
        u'29902 exit_group(0)                     = ?\n'
        u'29902 +++ exited with 0 +++\n'
        u'29900 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 29902\n'
        u'29900 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=29902, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---\n'
        u'29900 exit_group(0)                     = ?\n'
        u'29900 +++ exited with 0 +++\n'
    )
    monkeypatch.setattr(sys, 'argv', ['strace-process-tree', str(filename)])
    stp.main()
    output = capsys.readouterr().out
    assert output == (
        u"29900 /tmp/test.sh\n"
        u"  ├─29901 /usr/bin/printf 'hi\\n'\n"
        u"  ├─29902 /tmp/child.sh\n"
        u"  │   └─29903 /usr/bin/printf 'one\\n'\n"
        u"  └─29902 /tmp/another.sh\n"
        u"      └─29904 /bin/true\n"
    )


def test_main_force_color(monkeypatch, tmp_path, capsys):
    filename = tmp_path / "example.log"
    filename.write_text(
        u'29900 execve("/tmp/test.sh", ["/tmp/test.sh"], 0x7ffc5be66b48 /* 71 vars */) = 0\n'
    )
    monkeypatch.setattr(sys, 'argv', ['strace-process-tree', '-c', str(filename)])
    stp.main()
    output = capsys.readouterr().out
    assert output == (
        u"\033[31m29900\033[m \033[32m/tmp/test.sh\033[m\n"
    )


def test_main_force_no_color(monkeypatch, tmp_path, capsys):
    filename = tmp_path / "example.log"
    filename.write_text(
        u'29900 execve("/tmp/test.sh", ["/tmp/test.sh"], 0x7ffc5be66b48 /* 71 vars */) = 0\n'
    )
    monkeypatch.setattr(sys, 'argv', ['strace-process-tree', '--no-color', str(filename)])
    monkeypatch.setattr(stp.Theme, 'should_use_color', lambda: True)
    stp.main()
    output = capsys.readouterr().out
    assert output == (
        u"29900 /tmp/test.sh\n"
    )
