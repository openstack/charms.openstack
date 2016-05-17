# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
from setuptools.command.test import TestCommand

install_require = [
]

tests_require = [
    'tox >= 2.3.1',
]

class Tox(TestCommand):
    user_options = [('tox-args=', 'a', "Arguments to pass to tox")]
    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.tox_args = None
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True
    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import tox
        import shlex
        args = self.tox_args
        if args:
            args = shlex.split(self.tox_args)
        errno = tox.cmdline(args=args)
        sys.exit(errno)

setup(
    name='charm.openstack',
    version='0.0.1.dev1',
    description='Provide base module for layer-openstack.',
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "Topic :: System",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Software Distribution",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "License :: OSI Approved :: Apache Software License",
    ],
    url='https://github.com/WebsandHQ/websand3-config',
    author='Alex Kavanagh',
    author_email='alex.kavanagh@canonical.com',
    license='Apache-2.0: http://www.apache.org/licenses/LICENSE-2.0',
    packages=find_packages(exclude=["unit_tests"]),
    zip_safe=False,
    # test_suite='nose.collector',
    cmdclass = {'test': Tox},
    install_requires=install_require,
    extras_require={
        'testing': tests_require,
    },
    tests_require=tests_require,
)
