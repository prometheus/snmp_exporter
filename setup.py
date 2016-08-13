import os
from setuptools import setup

setup(
    name = "snmp_exporter",
    version = "0.0.6",
    author = "Brian Brazil",
    author_email = "brian.brazil@robustperception.io",
    description = ("SNMP exporter for the Prometheus monitoring system."),
    long_description = ("See https://github.com/prometheus/snmp_exporter/blob/master/README.md for documentation."),
    license = "Apache Software License 2.0",
    keywords = "prometheus exporter network monitoring snmp",
    url = "https://github.com/prometheus/snmp_exporter",
    scripts = ["scripts/snmp_exporter"],
    packages=['snmp_exporter'],
    test_suite="tests",
    # Also needs python-netsnmp per http://www.net-snmp.org/wiki/index.php/Python_Bindings
    install_requires=["prometheus_client>=0.0.11", "pyyaml"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: Apache Software License",
    ],
)
