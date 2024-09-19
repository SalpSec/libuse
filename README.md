# libUse

Simple CLI tool for finding all ELF binaries that use a given shared object through dynamic linking.

No proper formatting, multi-threading, sanity checks or anything is present.

# Usage
```
usage: libuse.py [-h] library path

Scan path for usage of library

positional arguments:
  library     library to scan for
  path        The path to scan

options:
  -h, --help  show this help message and exit
```
