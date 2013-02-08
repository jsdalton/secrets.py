try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import secrets

setup(
    name='secrets',
    version=secrets.__version__,
    packages=['secrets'],
    license='Creative Commons Attribution-Noncommercial-Share Alike license',
    long_description=open('README.md').read(),
    test_suite='nose.collector',
    tests_require=['nose', 'mock'],
    install_requires=['pycrypto'],
)
