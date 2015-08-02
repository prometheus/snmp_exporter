import os
from setuptools import setup

setup(
    name = "snmp_exporter",
    version = "0.0.3",
    author = "Brian Brazil",
    author_email = "brian.brazil@robustperception.io",
    description = ("Python client for the Prometheus monitoring system."),
    long_description = ("See https://github.com/brian-brazil/snmp_exporter/blob/master/README.md for documentation."),
    license = "Apache Software License 2.0",
    keywords = "prometheus exporter network monitoring snmp",
    url = "https://github.com/brian-brazil/snmp_exporter",
    scripts = ["scripts/snmp_exporter"],
    packages=['snmp_exporter'],
    test_suite="tests",
    install_requires=["prometheus_client>=0.0.11", "pyyaml", "pysnmp>=4.2.5"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: Apache Software License",
    ],
)
