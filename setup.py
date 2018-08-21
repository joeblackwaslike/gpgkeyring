import re
from setuptools import setup, find_packages


with open("gpgkeyring/__init__.py", "rt") as fd:
    version = re.search(
        r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', fd.read(), re.MULTILINE
    ).group(
        1
    )

if not version:
    raise RuntimeError("Cannot find version information")

try:
    from m2r import parse_from_file

    long_description = parse_from_file("README.md")
except ImportError:
    with open("README.md") as fd:
        long_description = fd.read()


setup(
    name="gpgkeyring",
    version=version,
    description="GnuPG2 Encryption and Key Management",
    long_description=long_description,
    keywords=[
        "gpg",
        "gnupg",
        "pgp",
        "crypto",
        "encryption",
        "key",
        "keys",
        "key management",
        "pki",
    ],
    author="Joe Black",
    author_email="me@joeblack.nyc",
    maintainer="Joe Black",
    maintainer_email="me@joeblack.nyc",
    url="https://github.com/joeblackwaslike/gpgkeyring",
    download_url=(
        "https://github.com/joeblackwaslike/gpgkeyring/tarball/v%s" % version
    ),
    license="MIT",
    install_requires=[
        "zope.configuration>=4.1.0",
        "zope.interface>=4.5.0",
        "zope.component>=4.4.1",
        "z3c.autoinclude>=0.3.7",
        "cachetools>=2.1.0",
        "python-gnupg>=0.4.2",
        "attrs>=18.1.0",
    ],
    zip_safe=False,
    packages=find_packages(),
    package_data={"": ["LICENSE"]},
    entry_points={"z3c.autoinclude.plugin": ["target = gpgkeyring"]},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development",
        "Topic :: Utilities",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
