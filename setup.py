import pathlib
from os import getenv
from setuptools import setup
requirements = pathlib.Path('requirements.txt')
install_requires = []
for line in requirements.read_text().splitlines():
    req = line.strip()
    if req.startswith('#'):
        continue
    install_requires.append(req)

setup(
    name='trivialsec-common',
    version=getenv('COMMON_VERSION'),
    url='https://www.trivialsec.com/',
    author='Christopher Langton',
    author_email='chris@trivialsec.com',
    packages=[
        'trivialsec/exceptions',
        'trivialsec/helpers',
        'trivialsec/models',
        'trivialsec/decorators',
        'trivialsec/services'
    ],
    classifiers=[
        'Programming Language :: Python :: 3.8',
        'Private :: Do Not Upload'
    ],
    install_requires=install_requires,
    include_package_data=True
)
