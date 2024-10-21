from os import path
from setuptools import setup
from setuptools import find_packages

version = "1.0.0"

install_requires = []


# read the contents of your README file

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.md")) as f:
    long_description = f.read()

# setup requires from requirements.txt
with open(path.join(this_directory, "requirements.txt")) as f:
    for l in f.readlines():
        if l.strip() != "" and l.strip()[0] != "#":
            install_requires.append(l.strip())

setup(
    name="certbot-dns-allinkl",
    version=version,
    description="All-Inkl DNS Authenticator plugin for Certbot",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/z3r0privacy/certbot-dns-allinkl",
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        "certbot.plugins": [
            "dns-allinkl = certbot_dns_allinkl.dns_allinkl:Authenticator"
        ]
    }
)