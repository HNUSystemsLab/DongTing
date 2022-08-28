#!/usr/bin/env python3
# -*- coding: utf-8 -*

"""[Internal] Cleaning of raw strace outputs for PLAID

    File is kept for historical reasons has no current use
"""

from pathlib import Path


def process_attack():
    out_path = Path("../data/PLAID/attack")

    files = Path("../data/PLAID_raw/attack_raw").rglob("*.txt*")
    for file in files:
        syscalls = []
        name = file.name.split("-")[0]
        trial = file.name.split("trial")[1].split(".txt")[0]
        pid = file.suffix[1:]
        # correct inconsistent naming
        if trial == "10":
            trial = 0
        with open(file) as f:
            lines = f.readlines()
            for line in lines:
                tmp = line[:3]
                if tmp == "+++" or tmp == "---":
                    continue
                syscalls.append(line.split("(")[0])
        out_dir = out_path / f"{name}_{trial}"
        out_dir.mkdir(exist_ok=True, parents=True)
        with open(out_dir / f"{pid}.txt", "w") as out:
            out.write(" ".join(syscalls))


def process_baseline():
    out_path = Path("../data/PLAID/baseline")
    files = Path("../data/PLAID_raw/baseline_raw").rglob("*.txt*")
    for file in files:
        syscalls = []
        name = file.name.split(".")[0]
        pid = file.suffix[1:]
        with open(file) as f:
            lines = f.readlines()
            for line in lines:
                tmp = line[:3]
                if tmp == "+++" or tmp == "---":
                    continue
                call = line.split("(")[0]
                if call[0] == ")":
                    continue
                syscalls.append(call)
        out_dir = out_path / name
        out_dir.mkdir(exist_ok=True, parents=True)
        with open(out_dir / f"{pid}.txt", "w") as out:
            out.write(" ".join(syscalls))


if __name__ == "__main__":
    process_attack()
    process_baseline()
