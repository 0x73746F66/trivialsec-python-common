from os import getenv
from setuptools import setup

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
    install_requires=[
        'flask>=2.0.1',
        'flask-login>=0.5.0',
        'flask-sessionstore>=0.4.5',
        'redis>=3.5.3',
        'mysql-connector-python>=8.0.25',
        'PyYAML>=5.4.1',
        'python-dotenv>=0.17.1',
        'passlib>=1.7<1.8',
        'boto3>=1.15<1.16',
        'botocore>=1.18<1.19',
        'retry>=0.9<1.0',
        'requests>=2.22<2.23',
        'python-dateutil>=2.8<2.9',
        'dnspython>=2.0.0<2.1.0',
        'python-http-client>=3.3<3.4',
        'sendgrid>=6.4<6.5',
        'starkbank-ecdsa>=1.0<1.1',
        'stripe>=2.51<2.52',
        'pysafebrowsing>=0.1.1<1.0',
        'pyOpenSSL>=19.1.0<20.0',
        'beautifulsoup4>=4.9.3<5.0',
        'stackprinter>=0.2.5',
        'gunicorn>=20.1.0',
        'setproctitle>=1.2.2',
        'mohawk>=1.1.0'
    ],
    include_package_data=True
)
