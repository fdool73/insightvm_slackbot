#!/usr/bin/env python
# Reference: https://github.com/kennethreitz/setup.py/blob/master/setup.py

# Standard Python libraries.
import io
import os
# import sys

# Third party Python libraries.
from setuptools import setup, find_packages  # , Command
# from shutil import rmtree

# Custom Python libraries.

# Package meta-data.
NAME = 'helpers'
DESCRIPTION = 'Helpers for automating vulnerability management scripts.'
URL = ''
EMAIL = ''
AUTHOR = ''
REQUIRES_PYTHON = '>=3.6.0'
VERSION = 0.1

# What packages are required for this module to be executed?
REQUIRED = [
    # 'requests', 'maya', 'records',
]

here = os.path.abspath(os.path.dirname(__file__))

# Import the README and use it as the long-description.
# Note: this will only work if 'README.md' is present in your MANIFEST.in file!
with io.open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = '\n' + f.read()

# Load the package's __version__.py module as a dictionary.
about = {}
if not VERSION:
    with open(os.path.join(here, NAME, '__version__.py')) as f:
        exec(f.read(), about)
else:
    about['__version__'] = VERSION

# Where the magic happens!
setup(
    name=NAME,
    version=about['__version__'],
    description=DESCRIPTION,
    long_description=long_description,
    author=AUTHOR,
    author_email=EMAIL,
    python_requires=REQUIRES_PYTHON,
    url=URL,
    packages=find_packages(exclude=()),
    # If your package is a single module, use this instead of 'packages':
    # py_modules=['helpers'],

    install_requires=REQUIRED,
    include_package_data=True  # ,
    # classifiers=[
    # Trove classifiers would go here
    # Full list: https://pypi.python.org/pypi?%3Aaction=list_classifiers
    # 'Programming Language :: Python :: 3.6'
    # ],
)
