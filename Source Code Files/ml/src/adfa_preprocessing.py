#!/usr/bin/env python3
# -*- coding: utf-8 -*

"""Fetches and decodes ADFA-LD

    Downloads ADFA-LD and converts it's integer encoding to the original system calls.
    Decoding is a best-effort process as the original authors of the dataset have lost the mapping.

"""

import shutil
import tarfile
import urllib
import zipfile
from pathlib import Path

import requests


def get_syscall_mapping(arch="x86_64", decode=True):
    mapping = dict()
    missed = []
    syscall_table = Path(f"../data/syscalls-{arch}.txt")
    if not syscall_table.exists():
        url = f"https://raw.githubusercontent.com/hrw/syscalls-table/master/tables/syscalls-{arch}"
        print(url)
        r = requests.get(url, allow_redirects=True)
        open(syscall_table, "wb").write(r.content)
    with open(f"../data/syscalls-{arch}.txt") as f:
        for line in f.readlines():
            parts = line.strip().split()
            call = parts[0]
            if len(parts) == 2:
                code = int(parts[1])
                if decode:
                    mapping[code] = call
                else:
                    for call in [call, *missed]:
                        mapping[call] = code
                    missed = []
            else:
                missed.append(parts[0])
    return mapping


def transcode(root_path, decode=True, arch="i386", dir_name="ADFA-LD_decoded"):
    errors = 0
    total = 0
    error_calls = set()
    mapping = get_syscall_mapping(arch=arch, decode=decode)
    for file in root_path.rglob("*.txt"):
        parts = list(file.parts)
        parts[2] = dir_name
        out_file = Path("/".join(parts))
        with open(file) as f:
            vals = f.readline().strip().split()
            if decode:
                vals = [int(x) for x in vals]
            line = []
            for val in vals:
                if val in mapping.keys():
                    line.append(mapping[val])
                else:
                    line.append(val)
                    errors += 1
                    error_calls.add(val)
                total += 1
                out_file.parent.mkdir(parents=True, exist_ok=True)
            if len(line):
                line = " ".join([str(x) for x in line])
                with open(out_file, "w") as out:
                    out.write(line)
    print(errors)
    print(error_calls)
    print(errors / total * 100)


def unpack_data():
    root_path = Path("../data/ADFA-LD")
    if not root_path.exists():
        urllib.request.urlretrieve(
            "https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-IDS-Datasets/ADFA-LD.zip",
            "data.zip",
        )
        with zipfile.ZipFile("data.zip", "r") as zip_ref:
            zip_ref.extractall("../data/")
        Path("data.zip").unlink()
        shutil.rmtree("../data/__MACOSX")

    if not Path("../data/PLAID").exists():
        with tarfile.open("../data/PLAID.tar.xz") as f:
            f.extractall(".")


if __name__ == "__main__":
    unpack_data()
    data_path = Path("../data/ADFA-LD")
    transcode(data_path, decode=True, arch="i386", dir_name="ADFA_decoded_i386")
