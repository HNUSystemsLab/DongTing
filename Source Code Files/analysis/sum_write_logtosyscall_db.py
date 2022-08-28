import re
import sre_parse
from re import sub
from os.path import join, abspath, dirname, split
from public.pub_fun_analysis import *
import time
import os

'''
Read the syscall analysis process information from the analyzed system call log/MLLOG, 
which is often used to return the source analysis process data and write it to the 
library. Add "_sum" to the name of the original table
'''

syscall_list_name = "kernel_syscallhook_bugpoc_trace_sum"
# out_txt_path = "poc_out_syz-step3"


class ff_readinfo():
    def __init__(self, src_file_path, pocsource, kelner_ver):
        self.src_file_path, self.pocsource, self.kelner_ver = src_file_path, pocsource, kelner_ver
        self.project_rootpath = abspath(dirname(__file__))
        self.srcfile_globalfull_path = join(self.project_rootpath, self.src_file_path)

    def _match_filename(self):
        file_names = []
        for root, dirs, files in os.walk(
                self.srcfile_globalfull_path):
            # print(os.path.join(root, file))
            for file in files:
                # print(file)
                file_names.append(join(root, file))
                # sum_file_name_list[file] = os.path.join(root, file)
        if len(file_names) == 0:
            print("The entered folder is empty, please check.")
        # print(file_names)
        return file_names

    def Matchalldata_Writedb(self):
        file_fullpath_list = self._match_filename()
        filetxt_path = self.srcfile_globalfull_path + "\\" + f"readme_analy_poclogbug{self.kelner_ver}.txt"
        print(filetxt_path)
        i = 0
        for file in file_fullpath_list:
            i += 1
            file_names = split(file)[1]
            if not file_names.endswith(".log"):
                continue
            file_name = file_names.split(".")[0].replace("sy_", "", 1)
            print(f"Working......ID:{str(i)},FN:{file_names}")

            cp = mydb[syscall_list_name].count_documents({"kshs_poclog_name": file_name})
            if cp > 0:
                seq_mycol = mydb[syscall_list_name].find_one({"kshs_poclog_name": file_name})
                if seq_mycol["kshs_bugpoc_syscall_counts"] > 1:
                    # Check the number of system calls, if it is greater than 1, it is a true duplicate,
                    # otherwise it can be recalculated
                    out_msg = f"---Duplicate: the data in the library contains the analysis result document " \
                              f"of the current file, please delete and write again.---"
                    print(out_msg)
                    continue
            else:
                con_state = False
                time1_end, time2_end = "", ""
                with open(file, "r", errors="ignore") as fs:
                    for line_mem in fs.readlines():
                        syscall_value = line_mem
                        doc_len = len(str(line_mem))  # Byte
                        line_syscall = line_mem.split("|")
                        syscall_list_counts = len(line_syscall)

                        con_state = True

                    if con_state == True:
                        k = 1000
                        kns_normal_seq_contents = "T" * (syscall_list_counts // k)

                        line_i = 0
                        with open(filetxt_path, "r", errors="ignore") as fs_txt:
                            group_strs = fs_txt.read().split("\n\n")
                            # print(f"分组数：{len(group_strs)}")
                            for con_g in group_strs:
                                con_str = con_g.strip().replace("\n", "")
                                if "---Success: " not in con_str:
                                    continue
                                else:
                                    name_str = con_str.split("FN:")[1].split("，")[0].split(".")[0]
                                    if name_str == "" or name_str != file_name:
                                        continue
                                    else:
                                        # print(name_str)
                                        time1_list = con_str.split("---", 1)
                                        if len(time1_list) < 1:
                                            continue
                                        time1_end = time1_list[0].split("：")[1]
                                        # print(time1_end)
                                        time2_list = con_str.split("Expend Time：")
                                        if len(time2_list) < 1:
                                            continue
                                        time2_end = time2_list[1].split("S")[0]
                        ke_kernel_ver = self.kelner_ver
                        kshs_poclog_name = file_name
                        kshs_pocsource_cls = self.pocsource
                        kshs_kernel_ver = ke_kernel_ver
                        kshs_bugpoc_syscall_list = syscall_value
                        kshs_bugpoc_syscall_mlcode = ""
                        kshs_bugpoc_syscall_counts = syscall_list_counts
                        kshs_bugpoc_wirte_time = time1_end
                        kshs_bugpoc_syscall_time = time2_end
                        kshs_syscall_size = doc_len  # Byte
                        kshs_bugpoc_contents = kns_normal_seq_contents

                        # write db
                        syscall_endlist = [{"kshs_poclog_name": kshs_poclog_name,
                                            "kshs_pocsource_cls": kshs_pocsource_cls,
                                            "kshs_kernel_ver": kshs_kernel_ver,
                                            "kshs_bugpoc_syscall_list": kshs_bugpoc_syscall_list,
                                            "kshs_bugpoc_syscall_mlcode": kshs_bugpoc_syscall_mlcode,
                                            "kshs_bugpoc_syscall_counts": kshs_bugpoc_syscall_counts,
                                            "kshs_bugpoc_wirte_time": kshs_bugpoc_wirte_time,
                                            "kshs_bugpoc_syscall_time": kshs_bugpoc_syscall_time,
                                            "kshs_syscall_size": kshs_syscall_size,
                                            "kshs_bugpoc_contents": kshs_bugpoc_contents
                                            }]

                        doc_len_kmg = str(list(Gmk_size(doc_len))[0]) + list(Gmk_size(doc_len).values())[0]
                        print(f"Syscall Data Size:{doc_len_kmg}.")
                        if doc_len < 15728640:
                            listwrite(syscall_list_name, syscall_endlist)
                        else:
                            syscall_endlist2 = [{"kshs_poclog_name": kshs_poclog_name,
                                                 "kshs_pocsource_cls": kshs_pocsource_cls,
                                                 "kshs_kernel_ver": kshs_kernel_ver,
                                                 "kshs_bugpoc_syscall_list": f"sy_{kshs_poclog_name}.log",
                                                 "kshs_bugpoc_syscall_mlcode": f"ml_{kshs_poclog_name}.log",
                                                 "kshs_bugpoc_syscall_counts": kshs_bugpoc_syscall_counts,
                                                 "kshs_bugpoc_wirte_time": kshs_bugpoc_wirte_time,
                                                 "kshs_bugpoc_syscall_time": kshs_bugpoc_syscall_time,
                                                 "kshs_syscall_size": kshs_syscall_size,
                                                 "kshs_bugpoc_contents": kshs_bugpoc_contents
                                                 }]
                            print("Greater than 15M, read-only LOG files, Syscall and ML do not write libraries.")
                            listwrite(syscall_list_name, syscall_endlist2)

                        out_msg = f"---Success: The {str(i)}rd POC Strace Log file was analyzed successfully，FN:{file_names}"
                        print(out_msg)

def Analy_main(folder, cls, kelner_ver):
    src_file_path = f"{folder}\\" if len(folder) > 0 else "srcdataattk\\"
    pocsource = cls if len(cls) > 0 else "syzbot"
    if src_file_path == "":
        print("The given directory is empty.")
    else:
        ff_readinfo(src_file_path, pocsource, kelner_ver).Matchalldata_Writedb()


# testing
if __name__ == '__main__':
    src_file_path = "srcdataattk"
    pocsource = "syzbot"
    kelner_ver = "4.15"
    Analy_main(src_file_path, pocsource, kelner_ver)
