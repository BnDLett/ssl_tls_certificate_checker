from setuptools import setup

setup(
    name='ssl-tls-certificate-checker',
    py_scipts=['ssl-tls-certificate-checker'],
    version='0.1.0',
    description='A project.',
    author='BnDLett',
    install_requires=[
        'pyOpenSSL',
        'cryptography'
    ],
)
