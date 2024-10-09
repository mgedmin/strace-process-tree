#!/usr/bin/env python
import ast
import os
import re

from setuptools import setup


here = os.path.dirname(__file__)
with open(os.path.join(here, "README.rst")) as f:
    long_description = f.read()

metadata = {}
with open(os.path.join(here, "strace_process_tree.py")) as f:
    rx = re.compile("(__version__|__author__|__url__|__licence__) = (.*)")
    for line in f:
        m = rx.match(line)
        if m:
            metadata[m.group(1)] = ast.literal_eval(m.group(2))
version = metadata["__version__"]

setup(
    name="strace-process-tree",
    version=version,
    author="Marius Gedminas",
    author_email="marius@gedmin.as",
    url="https://github.com/mgedmin/strace-process-tree",
    description="Produce a process tree from an strace log",
    long_description=long_description,
    long_description_content_type='text/x-rst',
    keywords="strace log process tree",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    license="GPL v2 or v3",
    python_requires=">=3.7",

    py_modules=["strace_process_tree"],
    zip_safe=False,
    entry_points={
        "console_scripts": [
            "strace-process-tree = strace_process_tree:main",
        ],
    },
)
