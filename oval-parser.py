#!/usr/bin/env python3

from packaging.version import Version
import xmltodict
import json
import re
import argparse
from tabulate import tabulate
import bz2
import requests
import logging
import time

logger = logging.getLogger(__name__)

description = """
Parse OVAL file to check for vulnerable and fixed CVEs.
"""

examples = """
Examples:
    python3 oval-parser.py --distro bionic --kernel 4.15.0-166
    python3 oval-parser.py --distro bionic --kernel 4.15.0-166 --savefile output.txt
    python3 oval-parser.py --distro bionic --ovalfile com.ubuntu.bionic.cve.oval.xml.bz2    
    python3 oval-parser.py --distro jammy --kernel 5.15.0-100
    python3 oval-parser.py --distro noble --kernel 6.8.0-40 --debug
""" 

fixed_regex = {
    "bionic": r"linux package in bionic.*?(4\.1[53]\.0-[0-9]+)",
    "focal": r"linux package in focal.*?(5\.4\.[0-9]+-[0-9]+)",
    "jammy": r"linux package in jammy.*?(5\.1[35]\.[0-9]+-[0-9]+)",
    "noble": r"linux package in noble.*?(6\.[568]\.[0-9]+-[0-9]+)",
}

def download_oval(distro):
    """
    Download the OVAL file for the specified distribution.

    Args:
        distro (str): The distribution to download the OVAL file for.

    Returns:
        str: The filename of the downloaded OVAL file.
    """
    filename = f"com.ubuntu.{distro}.cve.oval.xml.bz2"
    url = f"https://security-metadata.canonical.com/oval/{filename}"
    logger.debug(f"Downloading {url}")
    response = requests.get(url)
    with open(filename, "wb") as f:
        f.write(response.content)
    
    logger.debug(f"Downloaded to {filename}")
    return filename


def process_oval(xml, fixed_regex, kernel):
    """
    Process the OVAL XML data and extract CVE information.

    Args:
        xml (dict): The parsed OVAL XML data.
        fixed_regex (dict): Regular expressions for matching fixed versions.
        kernel (str): The kernel version to compare with.

    Returns:
        list: A list of CVE information, including CVE ID, severity, status, 
              whether it is up to date, and the fixed version.
    """
    cves = []
    for definition in xml["oval_definitions"]["definitions"]["definition"]:
        d_class = definition["@class"]
        if d_class == "vulnerability":
            description = definition["metadata"]["description"]
            severity = definition["metadata"]["advisory"]["severity"]
            cve = definition["metadata"]["advisory"]["cve"]["#text"]

            is_kernel = 0
            criteria = json.dumps(definition["criteria"]["criteria"])
            if re.search("Is kernel linux running", criteria):
                is_kernel = 1

            if is_kernel:
                status = "Vulnerable"
                match = re.search(fixed_regex, criteria)
                up_to_date = None
                fixed_version = None
                if match:
                    status = "Fixed"
                    up_to_date = True
                    fixed_version = match.group(1)
                    if kernel is not None:
                        if Version(kernel) < Version(fixed_version):
                            up_to_date = False
                cves.append([cve, severity, status, up_to_date, fixed_version])
    return cves


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=description, 
        epilog=examples, 
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--ovalfile", type=str, help="OVAL file to parse. Will download if not provided"
    )
    parser.add_argument(
        "--distro",
        type=str,
        help="Distro to parse",
        required=True,
        choices=["bionic", "focal", "jammy", "noble"],
    )
    parser.add_argument("--kernel", type=str, help="Kernel version to compare with")
    parser.add_argument("--savefile", type=str, help="Save output to file")
    parser.add_argument(
        "--debug",
        action="store_const",
        dest="loglevel",
        help="emit debug messages",
        const=logging.DEBUG,
        default=logging.INFO,
    )    

    args = parser.parse_args()
    
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    
    formatter.converter = time.gmtime
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(args.loglevel)
    
    if args.ovalfile is None:
        filename = download_oval(args.distro)
    else:
        filename = args.ovalfile

    with open(filename, "rb") as f:
        if filename.endswith(".bz2"):
            file_contents = bz2.decompress(f.read())
        else:
            file_contents = f.read()

    doc = xmltodict.parse(file_contents)

    data = process_oval(doc, fixed_regex[args.distro], args.kernel)
    headers = ["CVE", "Severity", "Status", "Up to date", "Fixed Version"]

    if args.savefile:
        with open(args.savefile, "w") as f:
            f.write(tabulate(data, headers=headers))
    else:
        print(tabulate(data, headers=headers))

    vuln = len([c for c in data if c[2] == "Vulnerable"])
    fixed_updated = len([c for c in data if c[2] == "Fixed" and c[3] == True])
    fixed_needsupdate = len([c for c in data if c[2] == "Fixed" and c[3] == False])
    logger.info(f"No. of vulnerable CVEs: {vuln}")
    logger.info(f"No. of fixed CVEs: {fixed_updated}")
    logger.info(f"No. of fixed CVEs that need update: {fixed_needsupdate}")
