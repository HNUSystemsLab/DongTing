from conn.dbconn import *
import time
import datetime
import random

'''
The program divides the dataset according to the extracted SEQ to provide a convenient benchmark for ML, 
and the main work details are as follows.
1, the selection of ML data: the main selection of training set, validation set and test set are 8:1:1, respectively.
2, data label classification: Abnormal and Normal two categories
3, data index: according to the default _id value of Mongodb.
4, data numbering structure: DT+a+_+P+b, where the value of ab, a = [1,18966], b = [1, 320]
Selection principles.
1, attack data to BUG as a benchmark, every 10 BUG as a group, 8 randomly selected for training data, draw 1 for 
validation data, draw 1 for test data, and then extract the SEQ according to the BUG (all extracted, the length can 
be selected during training).
2. Normal data, based on executable programs, every 10 programs as a warp, randomly draw 8 for training data, draw 1 
for validation data, draw 1 for test data.
'''

src_normal_db = "kernel_syscall_normal_strace"
src_attack_db = "kernel_syscallhook_bugpoc_trace_sum"

dst_conv_ml = "kernel_convert_baseline1"


class attact_conv_ml():
    def __init__(self):
        self.attack_cursor_list = []

    def _get_attack_db(self):
        # attack_cursor_list = []
        attack_name_list = []
        attack_poc_num = []
        # normal_cursor_list = []
        # test_i = 0
        mycol_defects = mydb[src_attack_db].find({}, {"_id": 0, "kshs_poclog_name": 1, "kshs_kernel_ver": 1,
                                                      "kshs_bugpoc_syscall_counts": 1, "kshs_syscall_size": 1})
        for cursor_mem in mycol_defects:
            self.attack_cursor_list.append(cursor_mem)
        mycol_defects.close()
        # Single POC start traversal
        for bug_info in self.attack_cursor_list:
            # test_i += 1
            if "_POC" in bug_info["kshs_poclog_name"]:
                bug_name = bug_info["kshs_poclog_name"].split("_POC")[0]
            else:
                bug_name = bug_info["kshs_poclog_name"]
            attack_name_list.append(bug_name)
        attack_name_list = list(set(attack_name_list))
        # print(test_i)
        # print(len(attack_name_list))
        return attack_name_list

    def _get_attack_bugpoc_count(self):  # Get the bugs and the number of POC in each bug
        attack_namenum_dict = {}
        attack_list = self._get_attack_db()
        end_bugname, end_bugname2 = "", ""
        for bug_name in attack_list:  # Read the list of bugs and count the number of POC of bugs
            # print(bug_name)
            bug_counts = 0
            for bug_men in self.attack_cursor_list:
                end_bugname = bug_men["kshs_poclog_name"]
                # print(end_bugname)
                if bug_name == end_bugname.split("_POC")[0]:
                    bug_counts += 1
                    end_bugname2 = end_bugname
                    # print(f"bug_name:{bug_name},bug_count:{bug_counts}")
            if bug_counts < 2:
                # print(end_bugname2)
                bug_name = end_bugname2
            attack_namenum_dict[bug_name] = bug_counts
            # attack_namenum_dict["bug_count"] = bug_counts

            with open("bug_name_num.txt", "w+") as fbug:
                for k, v in attack_namenum_dict.items():
                    # print(f"{k}:{v}")
                    fbug.write(f"{k}/{v}\n")
            # print(attack_namenum_dict)

        return attack_namenum_dict

    def _find_seq_group(self, bugname):
        seq_group_list = []
        for seq_men in self.attack_cursor_list:
            if bugname == seq_men["kshs_poclog_name"].split("_POC")[0]:
                seq_group_list.append(seq_men["kshs_poclog_name"])
        # print(seq_group_list)
        return seq_group_list

    def _get_poc_seq_info(self, pocname):
        # print(pocname)
        out_msg = {}
        for attack_cursor_mem in self.attack_cursor_list:
            if pocname == attack_cursor_mem["kshs_poclog_name"]:
                out_msg = attack_cursor_mem
                # print(out_msg)
        return out_msg

    def _cov_poc_seq_sim(self, tag_i, seq_bug_id, bug_name, bug_poc_counts, kcb_seq_class, seq_lables):
        kcb_bug_name = bug_name
        cp = mydb[dst_conv_ml].count_documents({"kcb_bug_name": bug_name})
        if cp > 0:
            print(f"Repeat, the current SEQ is already in the library, please clear it and rewrite it. BUGNAME：{bug_name}")
        else:
            seq_id = seq_bug_id
            # print(seq_id)
            kcb_seq_bug_id = seq_id.split("_")[0].replace("DT", "")
            kcb_seq_poc_id = seq_id.split("_")[1]
            poc_seq = self._get_poc_seq_info(kcb_bug_name)
            # print(poc_seq)
            kcb_master_line_ver = poc_seq.get("kshs_kernel_ver")
            kcb_syscall_counts = poc_seq.get("kshs_bugpoc_syscall_counts")
            kcb_syscall_sizes = poc_seq.get("kshs_syscall_size")
            # Current data segmentation results are written to the database
            bug_tag_list = [{"kcb_seq_id": seq_id,
                             "kcb_seq_bug_id": kcb_seq_bug_id,
                             "kcb_seq_poc_id": kcb_seq_poc_id,
                             "kcb_bug_name": bug_name,
                             "kcb_master_line_ver": kcb_master_line_ver,
                             "kcb_syscall_counts": kcb_syscall_counts,
                             "kcb_syscall_sizes": kcb_syscall_sizes,
                             "kcb_seq_lables": seq_lables,
                             "kcb_seq_class": kcb_seq_class,
                             "kcb_bl_time": time.asctime()
                             }]
            # listwrite(dst_conv_ml, bug_tag_list)

    def work_main(self):
        tag_i, all, i, j, k = 0, 0, 0, 0, 0
        h_i, h_j, h_k = 0, 0, 0
        attack_name_num = self._get_attack_bugpoc_count()
        kcb_seq_bug_id, kcb_seq_poc_id, kcb_bug_name, kcb_master_line_ver, kcb_syscall_counts, kcb_syscall_sizes, \
        kcb_seq_class = "", "", "", "", "", "", ""

        for bug_name in list(attack_name_num):
            all += 1
            seq_lables = "Abnormal"
            bug_poc_counts = attack_name_num[bug_name]
            ss = False
            if tag_i == 0:
                d_validation, d_test = 5, 8

            if tag_i > 9:
                d_validation = random.randint(1, 8)
                d_test = random.randint(1, 8)
                if d_validation == d_test:
                    d_test = random.randint(8, 9)
                tag_i = 0
                # print("#" * 30)
            tag_i += 1

            if tag_i == d_validation:
                kcb_seq_class = "DTDS-validation"
                j += 1
                # print(kcb_seq_class)
                # print(bug_name)
                # print(bug_poc_counts)
                if bug_poc_counts == 1:
                    h_j += 1
                    seq_bug_id = f"DTB{all}_P1"
                    # kcb_bug_name = self._find_seq_group(bug_name)[0]
                    self._cov_poc_seq_sim(tag_i, seq_bug_id, bug_name, bug_poc_counts, kcb_seq_class, seq_lables)
                    # print(end_list)
                else:
                    for poc_i in range(1, bug_poc_counts + 1):
                        h_j += 1
                        seq_bug_id = f"DTB{all}_P{poc_i}"
                        # kcb_bug_name = bug_name + "_POC" + str(poc_i)
                        # print(kcb_bug_name)
                        kcb_bug_name = self._find_seq_group(bug_name)[poc_i - 1]
                        self._cov_poc_seq_sim(tag_i, seq_bug_id, kcb_bug_name, bug_poc_counts, kcb_seq_class,
                                              seq_lables)
            elif tag_i == d_test:
                kcb_seq_class = "DTDS-test"
                k += 1
                # print(kcb_seq_class)
                # print(bug_name)
                # print(bug_poc_counts)
                if bug_poc_counts == 1:
                    h_k += 1
                    seq_bug_id = f"DTB{all}_P1"
                    # kcb_bug_name = self._find_seq_group(bug_name)[0]
                    self._cov_poc_seq_sim(tag_i, seq_bug_id, bug_name, bug_poc_counts, kcb_seq_class, seq_lables)
                    # print(end_list)
                else:
                    for poc_i in range(1, bug_poc_counts + 1):
                        h_k += 1
                        seq_bug_id = f"DTB{all}_P{poc_i}"
                        # kcb_bug_name = bug_name + "_POC" + str(poc_i)
                        # print(kcb_bug_name)
                        kcb_bug_name = self._find_seq_group(bug_name)[poc_i - 1]
                        self._cov_poc_seq_sim(tag_i, seq_bug_id, kcb_bug_name, bug_poc_counts, kcb_seq_class,
                                              seq_lables)
            else:
                kcb_seq_class = "DTDS-train"
                i += 1
                # print(kcb_seq_class)
                # print(bug_name)
                # print(bug_poc_counts)
                if bug_poc_counts == 1:
                    h_i += 1
                    seq_bug_id = f"DTB{all}_P1"
                    # kcb_bug_name = self._find_seq_group(bug_name)[0]
                    self._cov_poc_seq_sim(tag_i, seq_bug_id, bug_name, bug_poc_counts, kcb_seq_class, seq_lables)
                    # print(end_list)
                else:
                    for poc_i in range(1, bug_poc_counts + 1):
                        h_i += 1
                        seq_bug_id = f"DTB{all}_P{poc_i}"
                        # kcb_bug_name = bug_name + "_POC" + str(poc_i)
                        # print(kcb_bug_name)
                        kcb_bug_name = self._find_seq_group(bug_name)[poc_i - 1]
                        self._cov_poc_seq_sim(tag_i, seq_bug_id, kcb_bug_name, bug_poc_counts, kcb_seq_class,
                                              seq_lables)

            td_len = 100
            if all % td_len == 0:
                print(f"{int(all / td_len)}...", end="")
                print("") if all % (td_len * 20) == 0 else print("", end="")

        seq_all = h_i + h_j + h_k
        print(f"\n{seq_lables} Data Segmentation Summary:\n{seq_lables} BUGs：{all}（100%），SEQ number：{str(seq_all)}（100%）")
        print(f"DTDS-train BUGs：{i}（{str(100 * i / all)[0:5]}%），SEQ number：{h_i}（{str(100 * h_i / seq_all)[0:5]}%）")
        print(f"DTDS-validation BUGs：{j}（{str(100 * j / all)[0:5]}%），SEQ number：{h_j}（{str(100 * h_j / seq_all)[0:5]}%）")
        print(f"DTDS-test BUGs：{k}（（{str(100 * k / all)[0:5]}%），SEQ number：{h_k}（{str(100 * h_k / seq_all)[0:5]}%）")


class normal_conv_ml():

    def __init__(self):
        self.normal_cursor_list = []

    def _get_normal_db(self):
        normal_name_list = []
        mycol_defects = mydb[src_normal_db].find({}, {"_id": 0, "kns_normal_file_name": 1, "kns_normal_seq_counts": 1})
        for cursor_mem in mycol_defects:
            self.normal_cursor_list.append(cursor_mem)
        mycol_defects.close()
        # Single POC start traversal
        for bug_info in self.normal_cursor_list:
            bug_name = bug_info["kns_normal_file_name"]
            normal_name_list.append(bug_name)
        attack_name_list = list(set(normal_name_list))
        return attack_name_list  # Enter the list of bugs

    def _get_poc_seq_info(self, pocname):  # Get the SEQ information of the specified bug name
        out_msg = {}
        for normal_cursor_mem in self.normal_cursor_list:
            if pocname == normal_cursor_mem["kns_normal_file_name"]:
                out_msg = normal_cursor_mem
                # print(out_msg)
        return out_msg

    def _cov_poc_seq_sim(self, tag_i, seq_bug_id, bug_name, kcb_seq_class, seq_lables):
        kcb_bug_name = bug_name
        cp = mydb[dst_conv_ml].count_documents({"kcb_bug_name": bug_name})
        if cp > 0:
            print(f"Repeat, the current SEQ is already in the library, "
                  f"please clear it and rewrite it. BUGNAME：{bug_name}")
        else:
            seq_id = seq_bug_id
            # print(seq_id)
            kcb_seq_bug_id = seq_id.split("_")[0].replace("DT", "")
            kcb_seq_poc_id = seq_id.split("_")[1]
            poc_seq = self._get_poc_seq_info(kcb_bug_name)
            # print(poc_seq)
            kcb_master_line_ver = "5.12"
            kcb_syscall_counts = poc_seq.get("kns_normal_seq_counts")
            kcb_syscall_sizes = ""

            bug_tag_list = [{"kcb_seq_id": seq_id,
                             "kcb_seq_bug_id": kcb_seq_bug_id,
                             "kcb_seq_poc_id": kcb_seq_poc_id,
                             "kcb_bug_name": bug_name,
                             "kcb_master_line_ver": kcb_master_line_ver,
                             "kcb_syscall_counts": kcb_syscall_counts,
                             "kcb_syscall_sizes": kcb_syscall_sizes,
                             "kcb_seq_lables": seq_lables,
                             "kcb_seq_class": kcb_seq_class,
                             "kcb_bl_time": time.asctime()
                             }]
            listwrite(dst_conv_ml, bug_tag_list)

    def work_main(self):
        tag_i, all, i, j, k = 0, 0, 0, 0, 0
        h_i, h_j, h_k = 0, 0, 0
        normal_name_num = self._get_normal_db()
        kcb_seq_bug_id, kcb_seq_poc_id, kcb_bug_name, kcb_master_line_ver, kcb_syscall_counts, kcb_syscall_sizes, \
        kcb_seq_class = "", "", "", "", "", "", ""

        for seq_name in list(normal_name_num):
            all += 1
            seq_lables = "Normal"
            if tag_i == 0:
                d_validation, d_test = 5, 8

            if tag_i > 9:  # Fixed proposal every 10 draws
                d_validation = random.randint(1, 8)
                d_test = random.randint(1, 8)
                if d_validation == d_test:
                    d_test = random.randint(8, 9)
                tag_i = 0
                # print("#" * 30)
            tag_i += 1

            if tag_i == d_validation:
                kcb_seq_class = "DTDS-validation"
                j += 1
                # print(kcb_seq_class)
                # print(seq_name)
                h_j += 1
                seq_bug_id = f"DTN{all}_S1"
                self._cov_poc_seq_sim(tag_i, seq_bug_id, seq_name, kcb_seq_class, seq_lables)
            elif tag_i == d_test:
                kcb_seq_class = "DTDS-test"
                k += 1
                # print(kcb_seq_class)
                # print(seq_name)
                h_k += 1
                seq_bug_id = f"DTN{all}_S1"
                self._cov_poc_seq_sim(tag_i, seq_bug_id, seq_name, kcb_seq_class, seq_lables)
            else:
                kcb_seq_class = "DTDS-train"
                i += 1
                # print(kcb_seq_class)
                # print(seq_name)
                h_i += 1
                seq_bug_id = f"DTN{all}_S1"
                self._cov_poc_seq_sim(tag_i, seq_bug_id, seq_name, kcb_seq_class, seq_lables)

            td_len = 100
            if all % td_len == 0:  # Start counting when the LOG file is 100,000 lines
                print(f"{int(all / td_len)}...", end="")
                print("") if all % (td_len * 20) == 0 else print("", end="")

        seq_all = h_i + h_j + h_k
        print(f"\n{seq_lables} Data Segmentation Summary: \nNormals：{all}（100%），SEQ number：{str(seq_all)}（100%）")
        print(f"DTDS-train Normals：{i}（{str(100 * i / all)[0:5]}%），SEQ number：{h_i}（{str(100 * h_i / seq_all)[0:5]}%）")
        print(
            f"DTDS-validation Normals：{j}（{str(100 * j / all)[0:5]}%），SEQ number：{h_j}（{str(100 * h_j / seq_all)[0:5]}%）")
        print(f"DTDS-test Normals：{k}（（{str(100 * k / all)[0:5]}%），SEQ number：{h_k}（{str(100 * h_k / seq_all)[0:5]}%）")

# testing
if __name__ == '__main__':
    # Abnormal data flagging
    # check_attack = attact_conv_ml()
    # check_attack.work_main()
    attact_conv_ml().work_main()

    # Normal data flagging
    # check_normal = normal_conv_ml()
    # check_normal.work_main()
    normal_conv_ml().work_main()
