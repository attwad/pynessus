try:
    from setuptools import setup
    test_extras = {
        'test_suite': 'pynessus.test',
    }
except ImportError:
    from distutils.core import setup
    test_extras = {}


setup(
    name='pynessus',
    version='0.9',
    author='attwad',
    author_email='tmusoft@gmail.com',
    description=(
        'Library to talk to a remote Nessus 5 server that via its xmlrpc '
        'interface.'),
    long_description=open('README.rst').read(),
    url='https://github.com/attwad/pynessus',
    platforms='any',
    packages=[
        'pynessus',
        'pynessus.test',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Networking',
    ],
    **test_extras
)
