from re import sub
from os.path import join, abspath, dirname, split
from public.pub_fun_analysis import *
import time
import os

'''
1、Specify whether the file under the folder is in the library, check the file name
2、Check the sequence length distribution in the library
'''


class ff_path():
    def __init__(self, src_file_path, pocsource):
        self.src_file_path, self.pocsource = src_file_path, pocsource
        self.project_rootpath = abspath(dirname(__file__))
        self.srcfile_globalfull_path = join(self.project_rootpath, self.src_file_path)

    def _match_filename(self):
        file_names = []
        for root, dirs, files in os.walk(self.srcfile_globalfull_path):
            # print(os.path.join(root, file))
            for file in files:
                # print(file)
                file_names.append(join(root, file))
                # sum_file_name_list[file] = os.path.join(root, file)
        if len(file_names) == 0:
            print("The entered folder is empty, please check.")
        return file_names

    def Matchalldata_Writedb(self):
        file_fullpath_list = self._match_filename()
        tlb_list = get_tlb(1)
        tlb_name_list = get_tlb(2)
        tlb_nameandid_list = get_tlb(3)
        i, cp, noi, nocall, rei, logy, nolog, deli = 0, 0, 0, 0, 0, 0, 0, 0

        all_file_list = []
        cf_file_list = []
        failed_logname_list = []
        noanaly_logname_list = []
        max_file_list = []
        dep_del = False
        noin_list = []

        # 从文件路径中取单个的文件路径file
        for file in file_fullpath_list:
            i += 1
            file_names = split(file)[1]
            if not file_names.endswith(".log"):
                continue
            file_name = file_names.split(".")[0]
            file_name = file_name.replace("ml_", "")
            all_file_list.append(file_names)

            cp = mydb[syscall_list_name].count_documents({"kshs_poclog_name": file_name})
            if cp > 0:
                rei += 1
                if dep_del == True:  # Check for duplicates, remove identical items ！！！！！！！！！！！！！！
                    # seq_mycol = mydb[syscall_list_name].find_one_and_delete({"kshs_poclog_name": file_name})
                    print("If you need to delete the same, please modify the note code")
                else:
                    seq_mycol = mydb[syscall_list_name].find_one({"kshs_poclog_name": file_name})
                # print(seq_mycol)
                if seq_mycol["kshs_bugpoc_syscall_counts"] > 1:
                    # Check the number of system calls, if it is greater than 1, it is a true duplicate, otherwise it can be recalculated
                    out_msg = f"---Duplicate: the data in the library contains the analysis result document " \
                              f"of the current file, please delete and write again.---"
                    cf_file_list.append(file_names)
                    continue
                else:
                    print("Current POC LOG reanalysis")
            else:
                noi += 1
                print(f"Not in the library: {noi}")
                noin_list.append(file_name)
                print(f"The names of the files not in the table are: {file_name}")

        print(noin_list)
        print(f"Effective: {rei}")
        print(f"Not in the table: {noi}")


def Analy_main(folder, cls):
    src_file_path = f"{folder}\\" if len(folder) > 0 else "srcdataattk\\"
    pocsource = cls if len(cls) > 0 else "syzbot"
    if src_file_path == "":
        print("The given directory is empty.")
    else:
        ff_path(src_file_path, pocsource).Matchalldata_Writedb()


class seq_fbs():
    def __init__(self, syscall_list_name, value_in):
        self.syscall_list_name = syscall_list_name
        self.value_in = value_in

    def get_dblist(self):
        cursor_server_list = []
        ser_mycol = mydb[self.syscall_list_name].find({}, {"_id": 0, f"{self.value_in}": 1})
        for cursor_server_men in ser_mycol:
            cursor_server_list.append(cursor_server_men[self.value_in])
        ser_mycol.close()
        # print(cursor_server_list)
        return cursor_server_list

    def count_js(self, fbnum):
        count_list = self.get_dblist()
        js = 0
        for fi in count_list:
            if fi < (int(fbnum)):
                js += 1
        return js

    def count_js_area(self, min, max):
        count_list = self.get_dblist()
        # print(count_list)
        js = 0
        if min == 1:
            min = 0
        for fsum in count_list:
            if (fsum > (int(min))) and (fsum <= (int(max))):
                js += 1
        return js

    def to_kk(self, in_number):
        to_kk = 1000
        out_msg = ""
        check_num = int(in_number)
        if check_num <= to_kk:
            out_msg = check_num
        else:
            out_msg = str(int(check_num / to_kk)) + "K"
        return out_msg

    def fb(self, name):
        count_list = self.get_dblist()
        min_num = min(count_list)
        max_num = max(count_list)
        print(f"---Sequence distribution-{name}---")
        print(f"1、There are total sequence records {str(len(count_list))}. \n"
              f"2, the maximum value of the sequence length: {max_num}, the minimum value: {min_num}")
        q = 2
        prv_jy, prv_count = 0, 0
        end_num = 50000
        for jy in range(1, max_num, 500):
            q += 1
            if jy > end_num:
                break

        # Histogram data 1 (specified interval sampling)
        ksi = 0
        end_cw = 0

        group_fb = [1, 20, 30, 40, 60, 80, 100, 400, 700, 1000, 2000, 3000, 4000, 5000, 6000, 9000, 12000, 15000, 20000,
                    25000, 30000, 35000, 40000, 50000, 60000, 70000, 500000, 1000000, 4000000, 7000000]
        for fb_i in range(len(group_fb)):
            if fb_i == len(group_fb) - 1:
                end_cw = fb_i
                break
            ksi += 1
            out_num = self.count_js_area(group_fb[fb_i], group_fb[fb_i + 1])

            print(f"{self.to_kk(group_fb[fb_i]) if group_fb[fb_i] == 1 else self.to_kk(group_fb[fb_i] + 1)}-"
                  f"{self.to_kk(group_fb[fb_i + 1])}/{out_num}/{format(100 * out_num / len(count_list), '.3f')}")
        end_num = self.count_js_area(group_fb[end_cw], max(count_list))

        print(f"{self.to_kk(group_fb[end_cw])}-{self.to_kk(max(count_list))}/{end_num}/{format(100 * end_num / len(count_list), '.3f')}")
        print(f"The latter element {self.to_kk(group_fb[end_cw])}, Number of SEQs left: "
              f"{self.count_js_area(group_fb[end_cw], max(count_list))}({format(100 * self.count_js_area(group_fb[end_cw], max(count_list)) / len(count_list), '.2f')}), has been grouped into sample number {ksi + 1}.")
        print(f"End1: Number of sequences with a value range of 1 to 8: {self.count_js(8)} ({format(100 * self.count_js(8) / len(count_list), '.2f')}%)")
        print(f"End2: Number of sequences with a value range of 1-4495: {self.count_js(4495)} ({format(100 * self.count_js(4495) / len(count_list), '.2f')}%)")
        print(count_list)
        print(f"{self.count_js(10000)}/({format(100 * self.count_js(10000) / 12116, '.2f')}%)")


# testing
if __name__ == '__main__':

    work_id = 2

    if work_id == 1:
        syscall_list_name = "kernel_syscallhook_bugpoc_trace-t"  # Target library for comparison (note the deleted items, be sure to check ！！！！)
        src_file_path = "srcdataattk"
        pocsource = "syzbot"
        Analy_main(src_file_path, pocsource)

    elif work_id == 2:
        name = "Abnormal sequence distribution"
        syscall_list_name = "kernel_syscallhook_bugpoc_trace_sum"
        values = "kshs_bugpoc_syscall_counts"
        seq_fb = seq_fbs(syscall_list_name, values)
        # seq_fb.count_js_area(1,20)
        seq_fb.fb(name)

        name2 = "Normal sequence distribution"
        syscall_list_name2 = "kernel_syscall_normal_strace"
        values2 = "kns_normal_seq_counts"
        seq_fb2 = seq_fbs(syscall_list_name2, values2)
        seq_fb2.fb(name2)
