from conn.dbconn import *
from re import sub

'''
Centrally define some commonly used functions in the analysis process
'''


def Gmk_size(filesize):
    filesize = int(filesize)
    file_size_dict = {}  # file_size_k:file_size_v
    if not filesize == "":
        if filesize > 4 and filesize < 1024:
            file_size_dict[filesize] = "B"
        elif filesize > 1023 and filesize < 1024000:
            file_size_dict[format((filesize / 1024), ".2f")] = "KB"
        elif filesize > 1023999 and filesize < 1024000000:
            file_size_dict[format((filesize / 1024000), ".2f")] = "MB"
        elif filesize > 1023999999:
            file_size_dict[format((filesize / 1024000000), ".2f")] = "GB"
    # file_size_k:file_size_v
    # doc_len_kmg = str(list(Gmk_size(doc_len))[0]) + list(Gmk_size(doc_len).values())[0],其中doc_len为统计的字节数。
    return file_size_dict


def contain_str(linestr, srclist):
    return True if any(i in str(linestr) for i in srclist) else False


# Limit the size of the read file log
# Read large files will be memory overflow, then use the generator is can iterate feature,
# read on demand. Because the generator is generated only when it is used

# yield is return return a value, and remember this return position, the next
# iteration will start from this position after (next line)
def read_in_blocks(file_obj, block_size=209715200):  # 200M
    # default：1MB
    while True:
        data = file_obj.read(block_size)
        if not data:
            break
        yield data


def read_in_lines(file_obj, lines_size=100000000):
    while True:
        data = file_obj.readlines(lines_size)
        if not data:
            break
        yield data


def replacename(srcname):
    src_name = srcname.replace(":", "_").replace(" ", "_").replace("(", "_").replace(")", "_") \
        .replace(",", "_").replace("!", "_").replace("`", "_").replace(".", "_").replace("\\", "_") \
        .replace("/", "_").replace("<", "_").replace(">", "_").replace("-", "_").replace("'", "_") \
        .replace(";", "_").replace("“", "_").replace("’", "_").replace("?", "_").replace("@", "_") \
        .replace("$", "_").replace("&", "_")
    #   These have not been replaced yet
    # src_name_end = sub(r":| |, |)|,|!|`|.|\|/|<|>|-|'|;|“|’|?|@|$|&", "_", srcname)
    # print(src_name_end)
    src_name_end = src_name.replace("#", "_POC")
    return src_name_end


def get_tlb(cls_in):
    cls = str(cls_in)
    # cls:1\2\3,1: output all, 2 output the list of system call names, elements only system call names
    # \3 output list, elements of the dictionary composed of system calls and serial numbers
    cursor_tlb_list = []
    syscall_name_list = []
    syscall_seq = {}
    out_msg = ""

    tlb_mycol = mydb["kernel_syscall_x64tbl"].find({}, {"_id": 0, "syscall_number": 1, "syscall_name": 1, "syscall_tag": 1})
    for tlb_men in tlb_mycol:
        if tlb_men["syscall_tag"] == True:
            cursor_tlb_list.append(tlb_men)
            syscall_name_list.append(tlb_men["syscall_name"])
    tlb_mycol.close()

    if cls == "1":
        out_msg = cursor_tlb_list
    elif cls == "2":
        out_msg = syscall_name_list
    elif cls == "3":
        for syscall_dict_mem in cursor_tlb_list:
            syscall_seq[syscall_dict_mem["syscall_name"]] = syscall_dict_mem["syscall_number"]
            # print(syscall_seq)
        out_msg = syscall_seq
    return out_msg


def get_poc_c_name(cls_in, name_cls):  # Return the name of the POC containing C code
    # (name_cls:1 original name, 2 processed name), cls is 1, then the POC library is syzbot, 2 is exploit
    cls, name_cls = str(cls_in), str(name_cls)
    syzfixlistname = ""
    if cls == "syzbot":
        syzfixlistname = "kernel_fixed_l2_defect"
    elif cls == "exploitdb":
        syzfixlistname = "kernel_exploit_defect"
    pocc_cursor_list = []
    pocc_name = []
    poc_mycol = mydb[syzfixlistname].find({}, {"_id": 0, "l2def_defect_l1_name": 1, "l2def_crashes_kernelrelease": 1,
                                               "l2def_crashes_crepro": 1, "l2def_crashes_intrace": 1})
    for cursor_mem in poc_mycol:
        pocc_cursor_list.append(cursor_mem)  # Read the eligible fields into the list at once, each element is a KV
    poc_mycol.close()
    # all_poc = mydb[syzfixlistname].estimated_document_count()

    for pocc in pocc_cursor_list:
        # c_code = pocc["l2def_crashes_crepro"]
        # print(len(c_code))
        # print(pocc["l2def_defect_l1_name"])
        if pocc["l2def_crashes_crepro"] == None or len(pocc["l2def_crashes_crepro"]) <= 2:
            continue
        else:
            if name_cls == "1":
                pocc_name.append(pocc["l2def_defect_l1_name"])
            elif name_cls == "2":
                pocc_name.append(replacename(pocc["l2def_defect_l1_name"]))
    # print(pocc_name)
    return pocc_name


if __name__ == '__main__':
    syscall = get_tlb(2)
    print(len(syscall))
    print(syscall)
