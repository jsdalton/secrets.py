try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import secrets

setup(
    name='secrets.py',
    version=secrets.__version__,
    packages=['secrets'],
    license=open('LICENSE').read(),
    long_description=open('README.md').read(),
    test_suite='nose.collector',
    tests_require=['nose', 'mock'],
    install_requires=['pycrypto'],
)
