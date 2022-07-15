# setup.py
# CodeWriter21

from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()


setup(
    name='cryptwentyone',
    version='0.5.0',
    description='A fun package for cryptography',
    author='CodeWriter21',
    author_email='CodeWriter21@gmail.com',
    url='https://github.com/MPCodeWriter21/cryptwentyone',
    packages=find_packages(),
    license='Apache License, Version 2.0',
    classifiers=[
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
    ],
    long_description=long_description,
    long_description_content_type="text/markdown"
)
