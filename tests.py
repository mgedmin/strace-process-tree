# -*- coding: utf-8 -*-
import sys

import strace_process_tree as stp

import pytest


def test_events():
    # events() does several things:
    # - extracts the pid if present
    # - extracts the system call
    # - strips timestamps if present
    # - strip durations if present
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
        (27369, 'execve("bin/test", ["bin/test", "-pvc", "-t", "allowhosts.txt"], 0x7fffa04e8ba0 /* 71 vars */) = 0'),
        (27369, 'arch_prctl(ARCH_SET_FS, 0x7fbb38e89740) = 0'),
        (27369, 'clone(child_stack=0x7fbb371faff0, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 27370'),
        (27370, 'execve("/bin/sh", ["sh", "-c", "uname -p 2> /dev/null"], 0x55842eb789e0 /* 72 vars */) = 0'),
        (27370, '--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=27371, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---'),
        (27370, 'exit_group(0)     = ?'),
        (27370, '+++ exited with 0 +++'),
    ]


def test_events_bad_file_format():
    log_lines = [
        'Hello this is a text file and not an strace log file at all actually.',
    ]
    with pytest.raises(SystemExit):
        list(stp.events(log_lines))


def test_ProcessTree():
    pt = stp.ProcessTree()
    pt.handle_exec(42, 'foo')
    assert str(pt) == '42 foo\n'


def test_ProcessTree_simple_child():
    pt = stp.ProcessTree()
    pt.handle_exec(42, 'foo')
    pt.add_child(42, 43, 'bar')
    pt.add_child(42, 44, 'baz')
    assert str(pt) == (
        '42 foo\n'
        '  ├─43 bar\n'
        '  └─44 baz\n'
    )


def test_ProcessTree_unknown_parent_pid_and_name():
    pt = stp.ProcessTree()
    pt.add_child(None, 43, 'bar')
    pt.add_child(None, 44, 'baz')
    assert str(pt) == (
        '<unknown>\n'
        '  ├─43 bar\n'
        '  └─44 baz\n'
    )


def test_ProcessTree_unknown_parent_pid():
    pt = stp.ProcessTree()
    pt.handle_exec(None, 'foo')
    pt.add_child(None, 43, 'bar')
    pt.add_child(None, 44, 'baz')
    assert str(pt) == (
        '<unknown> foo\n'
        '  ├─43 bar\n'
        '  └─44 baz\n'
    )


def test_ProcessTree_exec_twice():
    pt = stp.ProcessTree()
    pt.handle_exec(42, 'foo')
    pt.add_child(42, 43, 'bar')
    pt.handle_exec(43, 'qux')
    assert str(pt) == (
        '42 foo\n'
        '  └─43 qux\n'
    )


def test_ProcessTree_exec_twice_with_children():
    pt = stp.ProcessTree()
    pt.handle_exec(42, 'foo')
    pt.add_child(42, 43, 'bar')
    pt.add_child(43, 44, 'baz')
    pt.handle_exec(43, 'qux')
    assert str(pt) == (
        '42 foo\n'
        '  ├─43 bar\n'
        '  │   └─44 baz\n'
        '  └─43 qux\n'
    )


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


def test_main_no_args(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['strace-process-tree'])
    with pytest.raises(SystemExit):
        stp.main()
    output = capsys.readouterr().err
    assert output.startswith(
        'usage: strace-process-tree [-h] [--version] [-v] filename\n'
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
