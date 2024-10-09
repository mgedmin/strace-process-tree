Changes
=======


1.5.1 (2024-10-09)
------------------

- Add support for Python 3.13.


1.5.0 (2024-04-19)
------------------

- Add support for Python 3.12.
- Recognize the clone3 system call (`issue 11
  <https://github.com/mgedmin/strace-process-tree/pull/11>`_).


1.4.0 (2023-06-27)
------------------

* Fix parsing ``/* 1 var */`` (`issue 9
  <https://github.com/mgedmin/strace-process-tree/pull/9>`_).
* Removed support for Python 2.


1.3.0 (2023-05-24)
------------------

* Support the NO_COLOR environment variable for disabling color autodetection
  (see https://no-color.org/).
* Fix parsing '<... syscall resumed>)' lines without a space in front of
  the closing parenthesis (`issue 5
  <https://github.com/mgedmin/strace-process-tree/issues/5>`_).


1.2.1 (2022-10-28)
------------------

* Add support for Python 3.8, 3.9, 3.10, and 3.11.
* Drop support for Python 3.5 and 3.6.
* Show line numbers when complaining about malformed input lines.
* Handle "[pid  NNN]" prefixes with more than one space.


1.2.0 (2019-08-23)
------------------

* Colorize the output if your terminal supports color.
* Command-line options --color/--no-color if you don't want autodetection.
* Use ASCII art if your locale does not support UTF-8.
* Command-line options --ascii/--unicode if you don't want autodetection.
* Speed up strace log parsing by 40%.


1.1.0 (2019-08-22)
------------------

* Show process running times when the strace log has timestamps
  (i.e. -t/-tt/ -ttt was passed to strace).
* Fix tree construction to avoid duplicating processes when execve()
  shows up in the log before the parent's clone() resumes.


1.0.0 (2019-08-21)
------------------

* Moved to its own repository on GitHub, added a README and this changelog.
* First release to PyPI.


0.9.0 (2019-08-01)
------------------

* Use Python 3 by default.


0.8.0 (2019-06-05)
------------------

* Parse more strace log variations: pids shown as "[pid NNN]", timestamps
  formatted as "HH:MM:SS.ssss" (strace -t/-tt versus -ttt that we already
  handled).


0.7.0 (2019-04-10)
------------------

* Do not lose information on repeated execve() calls.


0.6.2 (2019-04-10)
------------------

* PEP-8 and slight readability refactoring.


0.6.1 (2018-05-19)
------------------

* New strace in Ubuntu 18.04 LTS formats its log files differently.
* Recognize fork().


0.6.0 (2018-01-19)
------------------

* Use argparse, add help message.
* Better error reporting.
* Print just the command lines instead of execve() system call arguments
  (pass -v/--verbose if you want to see full execve() calls like before).
* execve() is more important than clone().
* Distinguish threads from forks.
* This was the last version released as a Gist.  Newer versions were available
  from `my scripts repository
  <https://github.com/mgedmin/scripts/blob/master/strace-process-tree>`__.


0.5.1 (2016-12-07)
------------------

* Strip trailing whitespace in output.


0.5.0 (2015-12-01)
------------------

* Handle strace -T output.
* Simplify clone() args in output.


0.4.0 (2015-11-18)
------------------

* Support vfork() and fork().


0.3.0 (2015-11-13)
------------------

* Support optional timestamps (strace -ttt).


0.2.3 (2014-11-14)
------------------

* Recommend strace options in --help message.
* Add a file containing example output.


0.2.2 (2013-05-29)
------------------

* Fix strace files that have two spaces between pid and event.


0.2.1 (2013-02-27)
------------------

* Add output example.
* Fix incorrect assumption that strace files always had two spaces between the
  pid and the event.


0.2 (2013-02-15)
----------------

* Add Unicode line art.


0.1 (2013-02-14)
----------------

* First public release as a GitHub Gist at
  https://gist.github.com/mgedmin/4953427
