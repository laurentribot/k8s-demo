#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from setuptools import setup, find_packages
try:
    from pkg_resources.extern import packaging
except ImportError:
    from pkg_resources import packaging


with open('VERSION') as f:
    project_version = f.read().strip()


def find_scripts():
    return [os.path.join('bin', x) for x in os.listdir(os.path.join(os.path.dirname(__file__), 'bin'))]


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


INVALID_VERSION = u'Version invalide. La version doit se conformer à la PEP 440.'
try:
    ver = packaging.version.Version(project_version)
    normalized_version = str(ver)
    if project_version != normalized_version:
        raise packaging.version.InvalidVersion(INVALID_VERSION)
except packaging.version.InvalidVersion:
    raise packaging.version.InvalidVersion(INVALID_VERSION)

with open('requirements.txt') as f:
    requirements = f.readlines()

setup(name='dlp-pki-dev',
      version=project_version,
      data_files=[],
      scripts=find_scripts(),
      package_dir={'': '.'},
      packages=find_packages(),
      package_data={'': ['static/*.html', 'templates/*.html'], 'static': ['*.html'], 'templates': ['*.html']},
      description='PKI de dev',
      url='http://git.sid.distribution.edf.fr/scm/plpint/dlp-pki-dev.git',
      author='DLP Integration',
      author_email='erdf-linky-dlp-integration@erdf.fr',
      long_description=read('README.rst'),
      license='Enedis',
      install_requires=requirements)
