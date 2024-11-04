# oval

Oval Manipulation Tools

### `oval-parser.py`

```
usage: oval-parser.py [-h] [--ovalfile OVALFILE] --distro
                      {bionic,focal,jammy,noble} [--kernel KERNEL]
                      [--savefile SAVEFILE] [--debug]

Parse OVAL file to check for vulnerable and fixed CVEs.

options:
  -h, --help            show this help message and exit
  --ovalfile OVALFILE   OVAL file to parse. Will download if not provided
  --distro {bionic,focal,jammy,noble}
                        Distro to parse
  --kernel KERNEL       Kernel version to compare with
  --savefile SAVEFILE   Save output to file
  --debug               emit debug messages

Examples:
    python3 oval-parser.py --distro bionic --kernel 4.15.0-166
    python3 oval-parser.py --distro bionic --kernel 4.15.0-166 --savefile output.txt
    python3 oval-parser.py --distro bionic --ovalfile com.ubuntu.bionic.cve.oval.xml.bz2    
    python3 oval-parser.py --distro jammy --kernel 5.15.0-100
    python3 oval-parser.py --distro noble --kernel 6.8.0-40 --debug
```
