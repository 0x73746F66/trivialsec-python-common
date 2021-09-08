import pathlib
from os import getenv
from setuptools import setup, find_packages

requirements = pathlib.Path('requirements.txt')
install_requires = []
for line in requirements.read_text().splitlines():
    req = line.strip()
    if req.startswith('#'):
        continue
    install_requires.append(req)

PACKAGES = find_packages(where="src")

setup(
    name='trivialsec-common',
    version=getenv('COMMON_VERSION'),
    url='https://www.trivialsec.com/',
    author='Christopher Langton',
    author_email='chris@trivialsec.com',
    packages=PACKAGES,
    package_dir={"": "src"},
    classifiers=[
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Private :: Do Not Upload'
    ],
    install_requires=install_requires,
    include_package_data=True,
    options={"bdist_wheel": {"universal": "1"}}
)
