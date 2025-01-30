"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import codecs
import os
import setuptools
import re


def get_version(filename):
    with codecs.open(filename, 'r', 'utf-8') as fp:
        contents = fp.read()
    return re.search(r"__version__ = ['\"]([^'\"]+)['\"]", contents).group(1)


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


version = get_version('scp_preprocessor/version.py')

setuptools.setup(
    name="scp-pre",
    packages=setuptools.find_packages(exclude=["*.tests", "*_tests"]),
    version=version,
    author="matluttr",
    author_email="matluttr@amazon.com",
    description="Preprocesses SCPs.",
    long_description=read('README.md'),
    long_description_content_type="text/markdown",
    url='https://github.com/aws-samples/service-control-policy-preprocessor',
    keywords='scp-preprocess aws iam SCP service control policy',
    license='MIT-0',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9'
    ],
    entry_points={"console_scripts": "scp-pre=scp_preprocessor.main:main"},
    python_requires='>=3.6',
    package_data={
        '': ['*.json']
    },
    install_requires=[
        'requests>=2.32'
    ]
)
