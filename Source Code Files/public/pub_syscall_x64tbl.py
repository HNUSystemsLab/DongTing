import os
from os.path import join
from conn.dbconn import *
from public.pub_fun_analysis import *
import time
import re

'''
Extract the system calls from the TLB file and store the system calls in the database tbl_db_list
This method reads a list of kernel system calls from the TLB file in the kernel (currently at 5.17.0).
The main points of the work are as follows:
(1) The copied tlb file is placed in the pubfile folder at the same level as this file, 
and no next-level root directory should be created.
(2) Extract the system calls from the TLB file and store the system calls in the database tbl_db_list.
'''

Root_path = os.path.abspath(os.path.dirname(__file__))
File_path = "pubfile\\syscall_64.tbl"
Srcfile_path = join(Root_path, File_path)

tbl_db_list = "kernel_syscall_x64tbl"


def tblfile_add_db():  # Capture the TLB table in the 5.17 kernel, written by system call sequence number
    i, oki = 0, 0
    with open(Srcfile_path, "r") as readfs:
        for line in readfs.readlines():
            line = line.strip()
            if ("#" in line) or len(line) == 0:
                continue
            i += 1
            new_line = list(filter(None, line.split("\t")))

            find_redo = mydb[tbl_db_list]
            cp = find_redo.count_documents({"syscall_number": new_line[0], "syscall_name": new_line[2]})
            if cp > 0:
                print(f"The same system call is available in the library, please verify. "
                      f"Duplicate information: ID:{new_line[0]},Name:{new_line[2]}")
                continue
            else:
                syscall_number = new_line[0]
                syscall_abi = new_line[1]
                syscall_name = new_line[2]
                syscall_entrypoint = "" if len(new_line) == 3 else new_line[3]

                syscall_endlist = [{"syscall_number": syscall_number,
                                    "syscall_abi": syscall_abi,
                                    "syscall_name": syscall_name,
                                    "syscall_entrypoint": syscall_entrypoint,
                                    "syscall_create_time": time.asctime(),
                                    "syscall_tag": True}]
                listwrite(tbl_db_list, syscall_endlist)
                oki += 1
                print(new_line)
    print(f"---The kernel standard system call {str(i)} was checked this time and {str(oki)} was successfully added.---")


if __name__ == '__main__':
    tblfile_add_db()
