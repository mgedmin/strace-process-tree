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
