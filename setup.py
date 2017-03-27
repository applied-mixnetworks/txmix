# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

from setuptools import setup


description = '''
    txmix is a twisted API for building mix networks
'''

setup(
    name='txmix',
    version='0.0.1',
    description=description,
    long_description=open('README.rst', 'r').read(),
    keywords=['python', 'mixnet', 'cryptography', 'anonymity'],
    install_requires=open('requirements.txt').readlines(),
    # "pip install -e .[dev]" will install development requirements
    extras_require=dict(
        dev=open('requirements-dev.txt').readlines(),
    ),
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Topic :: Security :: Cryptography',
        'Topic :: System :: Networking',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    license="GPLv3",
    packages=["txmix"],
)
