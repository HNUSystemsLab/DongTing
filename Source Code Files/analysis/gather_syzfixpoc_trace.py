import paramiko
from conn.dbconn import *
import os
from os.path import join
import time
import datetime
from tqdm import tqdm
from bson.objectid import ObjectId
from public.pub_network_test import *
from public.pub_fun_analysis import *
from analysis.gather_switch_vmkernel import *

'''
This program mainly implements reading C source file from DB, uploading it to the specified kernel server to compile 
and run, tracing it to get system calls, and then returning the result to local storage as LOG file.
Function description.
This method uses SSH login to the target server, then uploads the C test code of the POC to get the Syscall. 
The working points are as follows:
(1) read the list of servers from the templated text file, stored in the DB, and add tags
(2) read the list of servers for experiments after processing (in batches, whether to participate in experiments)
(3) read the POC content from the syzbot library
(4) upload to the target server, generate .
(5) Compile with GCC
(6) Upload LSMTRACE tracer/Use system installed tracer strace to test the compilation result
(7) Test timeout handling. Not timeout results are saved locally, timeout POC temporarily moved up to the server for testing
(8) Timeout process management
(9) Result collection and statistics

Instructions for use.
1、This program is suitable for windows/linux operating system as data operation terminal, remote for ubuntu system 
environment.
2、After connecting to the server, the working folder will be the current user's login folder.
3、The folder "poc_log/" is at the same level with this file, which is used to store the input results of poc by 
strace after tracking in the remote server, and the log files are distinguished by version.
4、Applicable to the trace test scenario using the system's own or upload tools, defined in tool_method.
5、When conducting automated testing, the data of the running server is stored in labserverinfo_input.txt. stored 
by format.
'''

#######################################################################
# V2 method, the program target should be able to create files to distinguish different server data
# Create the result folder with the target kernel kernel_ + version number + _local/remote
# e.g. create kernel_v5120_local and kernel_v5120_remote under poc_log
# System Security Research Team of AimLab
#######################################################################

Root_path = os.path.abspath(os.path.dirname(__file__))
Log_root_path = "poc_log" + "\\"
wait_time = 10
ewait_time = 60
Ept_dict = {}
poc_data_db = "kernel_fixed_l2_defect"  # The data table where the POC is located

sum_list_ok = []  # List of locally processed successful POCs
sum_list_bad = []  # List of POCs processed on the server
re_times = 0
vmre_times = 0  # Reboot notation in the Vm_reboot function


def Poc_state_mod(pocname):
    mod_yn = False
    pocall_mycol = mydb[poc_data_db].find({}, {"_id": 1, "l2def_defect_l1_name": 1, "l2def_crashes_intrace": 1})

    for poc_name_mem in pocall_mycol:
        if poc_name_mem["l2def_defect_l1_name"] == pocname:
            modpoc_mycol = mydb[poc_data_db]
            modpoc_mycol.update_one({"l2def_defect_l1_name": f"{pocname}"},
                                    {"$set": {"l2def_crashes_intrace": "false"}})
            mod_yn = True
        else:
            mod_yn = False
            continue
    return mod_yn


def Repeat_file_check(filename, logpathcls):  # Same name file detection, can detect one or more at a time,
    # when multiple, multiple files are separated by
    # filename: Pass in the value of the existence lookup (without the suffix), separated by , when there are multiple values
    linestr = filename.split(",") if filename.split(",") else [filename]
    filelists = []
    if filename != "":
        r_path = join(Root_path, Log_root_path, logpathcls)
        for parent, dirnames, filenames in os.walk(r_path):
            for filename in filenames:
                filelists.append(filename.split(".")[0])
    return True if any(i in linestr for i in filelists) else False


def Tqdm_bar(intotal):
    # Progress bar function
    intotals = int(intotal)
    time.sleep(1)
    file_size_ds = Gmk_size(intotals)  # file_size_k:file_size_v
    rang_s = int(list(file_size_ds)[0])
    for pb in tqdm(range(rang_s), position=0, total=rang_s, Ncols=80,
                   desc="Completed(" + list(file_size_ds.values())[0] + ")"):
        if intotals < 51201:
            time.sleep(0.0001)
        elif intotals > 51200 and intotals < 5120001:
            time.sleep(0.001)
        elif intotals > 5120001 and intotals < 102400001:
            time.sleep(0.05)
        elif intotals > 102400001 and intotals < 512000001:
            time.sleep(0.1)
        else:
            time.sleep(1.25)  # Estimated network speed of 10Mb, 1.25M/s
    time.sleep(0.1)


def Ver_contrast(dbver, inver):
    # Compare the first two bits, dbver input are characters, inver input is a list.
    # This function matches 2 bits strictly from left to right
    # inver = ["5.11"] # Write only the big version, when the subsequent check,
    # as long as it contains this version that run, such as ["5.10", "5.12"]
    result = False
    kversion = []
    if inver == "":
        kversion = [".", " "]
    elif "," in inver:
        if len(max(inver.split(","))) > 11:
            for new_list in inver.split(","):
                kversion.append(new_list[0:11])
        else:
            kversion = inver.split(",")
    else:
        kversion = [inver] if len(inver) < 12 else [inver[0:11]]

    at_kversion_db = dbver.split("-", 1)[0].split(".")
    if inver == "" and kversion[0] == ".":
        result = True
    elif len(kversion) > 0:
        for at_v_mem in kversion:
            at_kversion_in = at_v_mem.split(".")
            if at_kversion_db[0] == at_kversion_in[0] and at_kversion_db[1] == at_kversion_in[1]:
                result = True
    else:
        result = False
    return result, kversion


class SSH():
    def __init__(self, server_id, work_cls):
        ssh_labserver_db_name = "kernel_trace_dstserver"
        ssh_mycol = mydb[ssh_labserver_db_name].find_one({"_id": ObjectId(f"{server_id}")})
        # stats = ssh_mycol["ktd_info_complete"]
        self.sim_labserver_id, self.sim_vm_lots = ssh_mycol["_id"], ssh_mycol["ktd_info_lot"]
        self.work_cls = work_cls
        self.ip, self.user, self.pwd, self.rpwd, self.port = ssh_mycol["ktd_server_ip"], \
                                                             ssh_mycol["ktd_server_username"], \
                                                             ssh_mycol["ktd_server_userpwd"], \
                                                             ssh_mycol["ktd_server_rootpwd"], \
                                                             int(ssh_mycol["ktd_server_ssh_port"])
        self.timeout = 10
        self.tool_name, self.tool_method = ssh_mycol["ktd_labtool_name"], ssh_mycol["ktd_labtool_method"]

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(self.ip, username=self.user, port=self.port, password=self.pwd, timeout=self.timeout)

        self.sftp_trans = paramiko.Transport(sock=(self.ip, self.port))
        self.sftp_trans.connect(username=self.user, password=self.pwd)
        self.sftp_trans.set_keepalive(60)
        self.sftp_trans.banner_timeout = 300
        self.sftp = paramiko.SFTPClient.from_transport(self.sftp_trans)
        # print("-step 0: The POC analysis program is working.Conn ssh server is ok-")

    def _exec_command(self, in_command):
        # self._conn_server()
        command = in_command
        ssh_stdin, ssh_stdout, ssh_stderr = self.ssh.exec_command(command, get_pty=True)
        time.sleep(1)
        r_msg = ssh_stdout.read().decode()
        return r_msg

    def _test_rpath(self):
        rpath_command = "pwd"
        remote_path = self._exec_command(rpath_command)
        remotepath = remote_path.strip()
        return remotepath

    def _check_timeout(self, pocfilename, cls, pocsversion):
        check_time_yn = True  # True is ok
        out_msg = ""
        ps_out_all = ""
        exec_time_num_max, ci_times = 0, 0  # Call the time extraction function, get the most time consuming process,
        # and calculate the time consuming time
        check_ssht_error = ""
        if pocfilename in list(Ept_dict):
            print("Error: POC reached tagging condition, in the process of tagging...")
            mod_yn = Poc_state_mod(pocfilename)
            ps_out_all = ""
            check_time_yn = False
        else:
            # if check_time_yn == True:
            # print("check_time_test........")
            try:
                for ci in range(0, 10):
                    ci_times += 1
                    out_msg = ssh_test_single(self.ip, self.user, self.pwd, self.port)
                    time.sleep(2)
                    if out_msg == True:
                        try:
                            ps_out_all = self._exec_command(f"ps -eo etime,cmd | grep {self.tool_name}")
                        except Exception as ps_oa_error:
                            print(f"ps_oa_error:{ps_oa_error}")
                            continue
                        if len(ps_out_all) > 5:
                            check_time_yn = True
                            break
                        else:
                            ps_out_all = ""
                            check_time_yn = False
                            continue
                    else:
                        ps_out_all = ""
                        check_time_yn = False
                        continue

            except Exception as ssht_error:
                check_ssht_error = ssht_error
                ps_out_all = ""
                check_time_yn = False
                Ept_dict.update({f"{pocfilename}": 1})
                print("Tag addition completed")

        if ps_out_all != "" or check_time_yn == True:
            ps_out_ok_list = []
            exec_time_num = []
            check_list_bad = [";", "bash", "sudo", "grep"]
            for ps_out_all_mem in ps_out_all.split("\r\n"):
                ps_out_all_mem = ps_out_all_mem.strip().replace("./", "").replace(".out", "")
                if contain_str(ps_out_all_mem, check_list_bad) or len(ps_out_all_mem) == 0:
                    continue
                # print(ps_out_all_mem)
                if self.tool_name in ps_out_all_mem:
                    ps_out_ok_list.append(ps_out_all_mem)
            ps_out_end_list = list(filter(None, ps_out_ok_list))

            if len(ps_out_end_list) >= 1:
                for ps_out_ok_mem in ps_out_end_list:
                    exec_ps_out_ok_list = ps_out_ok_mem.split()
                    # print("name:%s" % outfilename)
                    if cls == 1:
                        if replacename(pocfilename) in exec_ps_out_ok_list:
                            check_list_time = exec_ps_out_ok_list[0].split(":")
                            if len(check_list_time) == 3:
                                exec_time = int(check_list_time[0]) * 60 * 60 + int(check_list_time[1]) * 60 + int(
                                    check_list_time[2])  # Process time, in seconds
                            else:
                                exec_time = int(check_list_time[0]) * 60 + int(
                                    check_list_time[1])  # Process time, in seconds
                            # print(exec_time)
                            exec_time_num.append(exec_time)  # List of process time consumption
                        else:
                            exec_time_num.append(0)  # If the current POC name is not detected,
                            # set the value to 60 and put it on the server to run
                    else:
                        check_list_time = exec_ps_out_ok_list[0].split(":",
                                                                       1)  # Split the elapsed time, and calculate the time in the next step
                        if len(check_list_time) == 3:
                            exec_time = int(check_list_time[0]) * 60 * 60 + int(check_list_time[1]) * 60 + int(
                                check_list_time[2])
                        else:
                            exec_time = int(check_list_time[0]) * 60 + int(check_list_time[1])
                        exec_time_num.append(exec_time)
                        # print(exec_time)
                exec_time_num_max = max(exec_time_num)
            else:
                exec_time_num_max = 0
        else:
            ername = pocsversion.split(".")[0] + "." + pocsversion.split(".")[1]
            fpath = join(Root_path, Log_root_path) + "sum_poc_workerror_" + ername + ".txt"
            with open(fpath, "a+") as ffs:
                ffs.write(f"Kernel Version: {pocsversion}\n")
                ffs.write(f"Function name: _check_timeout\n")
                ffs.write(f"Generation time: {time.asctime()}\n")
                ffs.write(f"POC name: {pocfilename}\n")
                ffs.write(f"Server failure, unable to record strace trace information.\n")
                ffs.write(f"check_ssht_error:{check_ssht_error}\r\n{'#' * 50}\n")
            exec_time_num_max = wait_time + 10
        return exec_time_num_max

    def _new_folder(self, logcls):
        # logcla two values, local generation, local generation LOG when the file name plus local, remote plus remote
        r_kver_comm = "uname -r"
        r_kver = self._exec_command(r_kver_comm)
        sub_foldername = r_kver.replace(".", "").replace("\r\n", "")
        if logcls == "local" or logcls == "remote":
            r_kver_foldename = "kernel_v" + sub_foldername + "_" + logcls + "_" + self.tool_name
            ex_path = join(Root_path, Log_root_path, r_kver_foldename)
            # print(ex_path)
            if not os.path.exists(ex_path):
                os.makedirs(ex_path)
            r_kver_msg = r_kver_foldename
            # print("mkdir ok")
        elif logcls == "rkversion":
            r_kver_msg = "kernel_v" + sub_foldername + "_" + self.tool_name
        else:
            print("Define directory name non-compliance!")
            r_kver_msg = "folder is error"
        return r_kver_msg

    def Get_syzfix_db(self, fixpocname):
        mycol = mydb[poc_data_db]
        for fix_value in mycol.find({"l2def_defect_l1_name": fixpocname}):
            self.fix_csourcecode = fix_value["l2def_crashes_crepro"]
        return self.fix_csourcecode

    def Conn_putcode_complie(self, src_name):
        remotepath = self._test_rpath()  # Remote Directory Detection
        outfilename = replacename(src_name)  # Create the file, using the new file name after processing
        src_name_endc = outfilename + ".c"
        comm_createfile = f"cd {remotepath};touch {src_name_endc}"
        self._exec_command(comm_createfile)
        # time.sleep(2)
        # print("-step 2: Create POC C file is ok-")

        # Write C code
        wftp = self.ssh.open_sftp()
        compliefile = (join(remotepath, src_name_endc).replace("\\", "/"))
        file = wftp.file(compliefile, "aw", -1)  # command="/home/aim/poc.c"
        file.write(self.fix_csourcecode)
        file.flush()
        wftp.close()
        # print("-step 3: Write POC code in C file is ok-")

        # Compile to executable file
        comm_complie = f"cd {remotepath};gcc -g {src_name_endc} -o {outfilename}.out"
        self._exec_command(comm_complie)
        # time.sleep(3)
        # print("-step 4: Complie C file is ok-")
        return outfilename

    def Exec_putfileandtest(self, pocsversion, fixpocname, toolmethod):
        remotepath = self._test_rpath()
        if toolmethod == "rtools":  # If executed for a remote tool, check the installation of the tool
            # The following is to check if strace is installed on the server side
            stracecheck_command = "strace -V"
            sc_msg = self._exec_command(stracecheck_command)
            sc_msg_v = sc_msg.split("\r\n")[0]
            check_keys = ["strace", "version"]
            if not contain_str(sc_msg_v, check_keys):  # No current strace keyword, then install
                aptinstall_command = f"echo {self.rpwd} | sudo -S apt-get install strace -y"
                self._exec_command(aptinstall_command)
        elif toolmethod == "ltools":  # Upload tool if executing as a local program
            refind_command = f"cd {remotepath};ls -l"
            out_msg = self._exec_command(refind_command)
            if self.tool_name not in out_msg:
                # put_file = paramiko.SFTPClient.from_transport(self.sftp_trans)
                localpath = join(Root_path, self.tool_name)  # self.tool_name is file name
                remotepath_end = (join(remotepath, self.tool_name).replace("\\", "/"))
                self.sftp.put(localpath, remotepath_end)
                self.sftp.chmod(remotepath_end, 0o777)
            self.sftp.close()
        # print(f"-step 5: Check {self.tool_name} or Up tool program is ok-")

        # Get syscall (enable command space separately)
        outfilename_ep = replacename(fixpocname)
        getsyscallhook_command = ""
        out_info_execput = ""

        if self.tool_method == "rtools":
            getsyscallhook_command = f"cd {remotepath};echo {self.rpwd} | sudo -S {self.tool_name} -v -f ./{outfilename_ep}.out"
            # -v Print out the complete environment variables, file stat structure, etc. Expand /* 25 vars */ in execve
        elif self.tool_method == "ltools":
            getsyscallhook_command = f"cd {remotepath};echo {self.rpwd} | sudo -S ./{self.tool_name} {outfilename_ep}.out"
        ssh_stdin_s, ssh_stdout_s, ssh_stderr_s = self.ssh.exec_command(getsyscallhook_command, get_pty=True)
        time.sleep(3)

        wait_step = 2  # Program execution or check time particles
        wait_times = int((wait_time // wait_step) + 1)
        time_max = 0
        lc_test = 0

        # The purpose of _check_timeout: to check if the getsyscallhook_command command is executed.
        # There are loops in the _check_timeout function, each time may be in 2S*times,will be greater than wait_step
        for per_times in range(0, wait_times):
            lc_test += 1
            time_max = self._check_timeout(fixpocname, 1, pocsversion)
            if (time_max > wait_time) or time_max < 1:
                break
            print(f"C{lc_test}...", end="")
            time.sleep(wait_step)
        if lc_test > 1:
            print("")  # No line break before the end

        exec_progress_time_max = time_max
        syscall_hook_msg = ""
        if exec_progress_time_max > wait_time:  # Judgment for remote execution
            print(f"-Elapsed time:{exec_progress_time_max}S,Example Enable remote Log storage.-")
            try:
                sshtest = ssh_test_single(self.ip, self.user, self.pwd, self.port)
                if sshtest == True:
                    # print("qq12")
                    # print(f"sshtest：{sshtest}")
                    getsyscallhook_command_pm = ""
                    if self.tool_method == "rtools":
                        getsyscallhook_command_pm = f"echo {self.rpwd} | sudo -S nohup {self.tool_name} -v -f ./{outfilename_ep}.out > {outfilename_ep}.log"
                    elif self.tool_method == "ltools":
                        getsyscallhook_command_pm = f"echo {self.rpwd} | sudo -S nohup ./{self.tool_name} {outfilename_ep}.out > {outfilename_ep}.log"
                    nohup_send = self.ssh.invoke_shell()
                    nohup_send.send(f"{getsyscallhook_command_pm} & \n")
                    time.sleep(1)
                    syscall_hook_msg = f"The time-consuming poc<remote-log>, the trace results will be saved in a " \
                                       f"specified directory on the server named:{outfilename_ep}.log"
                    sum_list_bad.append({pocsversion: fixpocname})
                else:
                    raise
            except Exception as execput_error:
                out_info_execput = f"execput_error:{execput_error}"
                print(out_info_execput)
                # Exec_putfileandtest execution does not pass, the key module of this trace function, need to re-test the whole
                Analysis_main(self.work_cls, "stopadd", self.sim_vm_lots)
        else:
            sum_list_ok.append({pocsversion: fixpocname})
            syscall_hook_msg = ssh_stdout_s.read().decode()

        try:
            for nf in range(0, 3):  # Accelerated exception throwing
                log_lfolder_name = self._new_folder(
                    "local")  # Use remote server kernel version checking or create LOG local subdirectory
                if log_lfolder_name != "":
                    break
        except:
            raise
        pt_log_path = join(Log_root_path, log_lfolder_name) + "/"
        with open(pt_log_path + replacename(fixpocname) + ".log", "w") as pocendfs:
            syscall_hook_msg_end = "localpocname:" + fixpocname + "\n" + syscall_hook_msg  # The POC name is written in the
            # line header and labeled as localpoc during data processing:
            pocendfs.write(syscall_hook_msg_end)
        # print("-step 7: Output POC syscall and hook is ok-")
        return syscall_hook_msg

    def Exec_working(self, in_workversion):  # Target mainline version for incoming analysis
        kversion = ()  # Versioning returns a tuple
        cok, cno, noi, reid, alls, tagi, Nonei = 0, 0, 0, 0, 0, 0, 0
        analysis_succ = ""  # Mark POC execution as successful or not
        rework_times = 0  # Mark the number of times the same POC was not executed successfully
        out_info_exec = ""
        defect_cursor_list = []

        log_lfolder_name = self._new_folder(
            "local")  # Use remote server kernel version checking or create LOG local subdirectory
        if poc_data_db not in mydb.list_collection_names():
            out_info_exec = f"Input error: set“ {poc_data_db} ”does not exist in DB."
        else:
            mycol_defects = mydb[poc_data_db].find({}, {"_id": 0, "l2def_defect_l1_name": 1,
                                                        "l2def_crashes_kernelrelease": 1,
                                                        "l2def_crashes_crepro": 1, "l2def_crashes_intrace": 1})
            for cursor_mem in mycol_defects:
                defect_cursor_list.append(cursor_mem)
            mycol_defects.close()
            # Single POC start traversal
            for fixpoc_infos in defect_cursor_list:
                kversion = Ver_contrast(fixpoc_infos["l2def_crashes_kernelrelease"], in_workversion)
                if kversion[0]:
                    alls += 1
                    if fixpoc_infos["l2def_crashes_intrace"] == False or fixpoc_infos[
                        "l2def_crashes_intrace"] == "false":
                        tagi += 1
                        continue
                    if fixpoc_infos["l2def_crashes_crepro"] == None or len(fixpoc_infos["l2def_crashes_crepro"]) <= 2:
                        Nonei += 1
                        continue

                    if len(fixpoc_infos["l2def_crashes_crepro"]) > 2:
                        cok += 1
                        try:
                            # if cok > 10:
                            #     break
                            fixpocname = fixpoc_infos["l2def_defect_l1_name"]  # POC name
                            if Repeat_file_check(replacename(fixpocname), log_lfolder_name):
                                # Compare with local files to check whether the POC has been analyzed
                                print(f"Repeat, the current POC has been analyzed, ID: {str(cok)}, "
                                      f"please clear it and re-analyze it. POCNAME：{fixpocname}")
                                reid += 1
                                continue
                            self.Get_syzfix_db(fixpocname)
                            # print(f"-step 1: Get POC C source code is ok-,POC name:{fixpocname}")
                            print(f"-Working...... POC version <{fixpoc_infos['l2def_crashes_kernelrelease']}>，"
                                  f"Analysis in progress: <{fixpocname}>-")
                            self.Conn_putcode_complie(fixpocname)
                            self.Exec_putfileandtest(fixpoc_infos["l2def_crashes_kernelrelease"], fixpocname,
                                                     self.tool_method)
                            analysis_succ = True
                            print(f"---This time the syscal of the {str(cok)} POC was successfully "
                                  f"analyzed. NAME：<{fixpocname}>---")
                            time.sleep(1)

                        except Exception as gather_error:
                            sshtest_reon = False
                            noi += 1
                            rework_times += 1
                            print(f"Exec_working error information: {gather_error}")

                            if gather_error == "SSH session not active":
                                print("R00")
                                Vm_reboot(self.sim_labserver_id)
                                # print("R01")
                                continue
                            else:
                                try:
                                    sshtest_reon = ssh_test_single(self.ip, self.user, self.pwd, self.port)
                                    print(f"ssh_test Results:{sshtest_reon}")
                                except Exception as gather_error_rssh:
                                    sshtest_reon = False
                                    # print("R2")
                                    print(f"gather_error_rssh:{gather_error_rssh}")
                                    time.sleep(10)
                                    continue
                                finally:
                                    if sshtest_reon == True:
                                        print(f"analysis_succ:{analysis_succ}")
                                        if analysis_succ == False:
                                            Vm_reboot(self.sim_labserver_id)
                                        continue
                                    else:
                                        Analysis_main(self.work_cls, "stopadd", self.sim_vm_lots)
                    else:
                        continue
                else:
                    continue

        # tagi = len(list(Ept_dict))
        loki = len(sum_list_ok)
        roki = len(sum_list_bad)
        loki_per = 100 * loki / (loki + roki) if loki > 0 else 0
        roki_per = 100 * roki / (loki + roki) if roki > 0 else 0
        sum_path = join(Root_path, Log_root_path, log_lfolder_name).replace("\\", "/") + "/"
        sk_ver_comm = "uname -r"
        sk_ver_msg = self._exec_command(sk_ver_comm)
        kversion_ies = "-".join(kversion[1])
        sum_filename = ((f"sum_poc_work_{kversion_ies}-in-{sk_ver_msg}-"
                         f"{time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime())}").replace(".", "") +
                        f".log").replace("\r\n", "")
        msg_3_1 = f"\nTotal analysis sequence files: (all POC numbers, Data-A01) {str(alls)}, With C code(noTag-POC " \
                  f"number，Data-A02) {str(cok)}, Marked (Tag-POC number，Data-A03) {str(tagi)} .\n" \
                  f"---Summary of C code (noTag-POC) analysis results---\n" \
                  f"(1)Analysis of the POC contains a total of C code sequence files: {str(cok)};\n" \
                  f"(2)enerate local (single execution time<5S，Data-A0201)LOG: {str(loki)} ({str(loki_per)[0:5]} %);\n" \
                  f"(3)Generate remote (single execution time > 5S), Data-A0202)LOG: {str(roki)} ({str(roki_per)[0:5]} %);\n" \
                  f"(4)Duplicate with local {reid} ;\n" \
                  f"(5)POC's C code is empty or None {Nonei};\n" \
                  f"(6)Errors {noi} .\r\n" \
                  f"---Summary of C code (Tag-POC) analysis results---\n" \
                  f"(1)Analysis of Tag-POC files total:(Data-A03) {str(tagi)};\n"
        with open(sum_path + sum_filename, "w+") as sfs:
            sfs.write(f"---Remote server kernel version---\n{sk_ver_msg} \r\n")
            sfs.write("---Current kernel mainline version of the analysis POC---\n")
            sfs.write(kversion_ies + "\n")
            sfs.write(
                f"\r\n---POC, version details of local retrieval results---\n---Current Time {time.asctime()}---\n")
            for sum_ok in sum_list_ok:
                sfs.write("%s: %s \n" % (list(sum_ok)[0], list(sum_ok.values())[0]))
            sfs.write(
                f"\r\n---Push the POC, version details running in the remote server---\n---Current Time {time.asctime()}---\n")
            for sum_bad in sum_list_bad:
                sfs.write("%s: %s \n" % (list(sum_bad)[0], list(sum_bad.values())[0]))
            sfs.write(
                f"\r\n---Details of the POC version that was marked (with C code)---\n---Current Time {time.asctime()}---\n")

            for fixpoc_tag in defect_cursor_list:
                kversion_tag = Ver_contrast(fixpoc_tag["l2def_crashes_kernelrelease"], in_workversion)
                if kversion_tag[0] and (
                        fixpoc_tag["l2def_crashes_intrace"] == False or fixpoc_tag["l2def_crashes_intrace"] == "false"):
                    sfs.write("%s\n" % fixpoc_tag["l2def_defect_l1_name"])
            # for tag_k in list(Ept_dict):
            #     sfs.write("%s\n" % tag_k)

            sfs.write(msg_3_1)
            # ###### end  ##################
        # print(msg_3_1)  #
        return msg_3_1

    # KILL process
    def Exec_Killpid(self):
        k_oki = 0
        pid_list = []
        kname_list = []
        k_command = f"ps -eo pid,etime,cmd | grep {self.tool_name}"
        out_msg = self._exec_command(k_command)
        # print(out_msg)
        log_rfolder_name = self._new_folder(
            "remote")  # Use remote server kernel version checking or create a local subdirectory for downloading remote LOGs
        if out_msg != "":
            pid_check_list_bad = [";", "bash", "grep"]  # Filtering irrelevant records in PS results
            out_msg_list = out_msg.split("\r\n")
            out_msg_list = list(filter(None, out_msg_list))
            for killpid_all_men in out_msg_list:
                killpid_men = killpid_all_men.strip()
                if contain_str(killpid_men, pid_check_list_bad):
                    continue
                # Filtering to get the right PS records
                killpid_men_list = killpid_men.replace("    ", "#|").replace(f"{self.tool_name} ", "#|").split("#|")
                pid_list.append(killpid_men_list[0])
                kname_list.append(killpid_men_list[2])
            pid_list = list(filter(None, pid_list))
            kname_list = list(set(kname_list))

        if len(pid_list) < 1:
            msg_3_2 = "The POC process is fully executed."
        else:
            print(f"Warning!  This will clear all {self.tool_name} processes in the server under test, "
                  f"will wait 10 seconds, if you do not intend to execute, please abort the program.")
            time.sleep(10)
            for kill_pid in pid_list:
                k_oki += 1
                killl_pid_command = f"echo {self.rpwd} | sudo -S kill -9 {kill_pid}"
                kp_send = self.ssh.invoke_shell()
                kp_send.send(f"{killl_pid_command} & \n")
                time.sleep(2)
                print(f"---Successfully abort the {str(k_oki)}th process, PID: {kill_pid}---")

            kp_path = join(Root_path, Log_root_path, log_rfolder_name) + "\\"
            kp_filename = f"sum_poc_kill_{time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime())}" + ".log"
            with open(kp_path + kp_filename, "w+") as kfs:
                kfs.write(f"---The number of POCs that are currently forcibly suspended from running "
                          f"(Data-A0203) {str(len(kname_list))} with the following names---\n")
                kfs.write("Tips: \n (1) forced to abort the POC, often for two main cases: one constantly dead loop,"
                          " will not automatically abort; the other is triggered by a bug, the process hangs.\n"
                          "(2) Note the aborted POC process, which is only used as a reference for syscall or "
                          "Hook extraction because it is incomplete.\r\n")
                msg_3_end = f"Total number of aborted processes: {str(k_oki)} 个。\n"
                msg_3_2 = f"\n---Summary of the results of the discontinuation process---\n{time.asctime()} {msg_3_end}\n" \
                          f"Name of the POC that was forcibly suspended: \r\n"
                kfs.write(msg_3_2)
                for kpocname in kname_list:
                    kfs.write(kpocname + "\n")
                # msg_3_2 = msg_3_2 + kname_list
        return msg_3_2

    # downloaded LOG
    def Exec_getlog(self):

        # gl_rpath = join(self._test_rpath(), "//")
        gl_rpath = self._test_rpath()
        gl_sftpc = self.ssh.open_sftp()
        gl_rfiles = gl_sftpc.listdir(gl_rpath)
        # print(gl_rfiles)
        log_ok = False
        for logt in gl_rfiles:
            if logt.endswith(".log"):
                log_ok = True
        log_rfolder_name = self._new_folder("remote")  # Use remote server kernel version checking or
        # create a local subdirectory for downloading remote LOGs

        if log_ok:
            nflogall = nflog_ok = nflog_able = nflog_re = nflog_err = nodown_log = tar_log = redown = 0
            for gl_rfile in gl_rfiles:
                try:
                    if "\\" in gl_rfile:
                        print("utf8 error")
                        continue
                    if gl_rfile.endswith(".log"):
                        # nflogall += 1
                        nflogall += 1
                        gl_rfile_path = gl_rpath + "/" + gl_rfile
                        psize = gl_sftpc.stat(gl_rfile_path)
                        filesize = psize.st_size
                        print(f"---Retrieved the first {str(nflogall)} remote log file, NAME:<{gl_rfile}>---")

                        if filesize < 5:  # Less than 5 bytes, re-execute
                            nflog_re += 1
                            r_lfilename = gl_rfile.split(".", 1)[0]
                            if self.tool_method == "rtools":
                                r_command = f"echo {self.rpwd} | sudo -S nohup {self.tool_name} -v -f ./{r_lfilename}.out > {gl_rfile}.log"
                            else:
                                r_command = f"echo {self.rpwd} | sudo -S nohup ./{self.tool_name} {r_lfilename}.out > {gl_rfile}.log"
                            nohup_send = self.ssh.invoke_shell()
                            nohup_send.send(f"{r_command} & \n")
                            print(f"---Successfully re-execute the {str(nflog_re)} remote POC file.---")
                        else:
                            nflog_able += 1
                            # file_size_k = int(psize.st_size/1024/1024)  # MB
                            file_size_d = Gmk_size(filesize)  # file_size_k:file_size_v
                            print(f"Working...... Filesize: {list(file_size_d)[0]} {list(file_size_d.values())[0]}，",
                                  end="")
                            if Repeat_file_check(gl_rfile.split(".")[0], log_rfolder_name):
                                redown += 1
                                print(f"Repeat! The current LOG has been downloaded, clear it and try again.")
                                continue
                            else:
                                # print("%s : %d Byte" % (gl_rfile, file_size_k))
                                rinl_path = join(Root_path, Log_root_path, log_rfolder_name) + "/"
                                gl_local_file_path = rinl_path + gl_rfile
                                if filesize > 40960000000:  # >10GB=10 240 000 000
                                    nodown_log += 1
                                    print("If the file size is larger than 40G, you need to change the download "
                                          "method or consider the necessity of downloading.")
                                elif filesize > 10240000 and filesize < 40960000001:  # >10MB=10 240 000,<40G
                                    tar_log += 1
                                    print("Capacity greater than 10MB, compression in progress...", end="")
                                    tar_command = f"tar -zcvf {gl_rfile}.tar {gl_rfile}"
                                    tar_msg = self._exec_command(tar_command)
                                    # print(tar_msg)
                                    gl_rfile_path_tar = gl_rpath + "/" + gl_rfile + ".tar"
                                    gl_local_file_path_tar = rinl_path + gl_rfile + ".tar"
                                    print("Download in......", end="")
                                    self.sftp.get(gl_rfile_path_tar, gl_local_file_path_tar)
                                    print(f"Download successful")
                                else:
                                    nflog_ok += 1
                                    # self.sftp.get(gl_rfile_path, gl_local_file_path, callback=tqdm_bar(filesize))
                                    self.sftp.get(gl_rfile_path, gl_local_file_path)
                                    print(f"Download successful")
                except:
                    nflog_err += 1
                    continue
            msg_3_3 = f"Total number of remote LOG files analyzed: {str(nflog_able)}" \
                      f"Reimplementation: {str(nflog_re)} ({str(100 * nflog_re / nflogall)[0:5]} %)," \
                      f"Duplicate with local {redown} ({str(100 * redown / nflogall)[0:5]} %);" \
                      f"\nThis download LOG (<10M)：{str(nflog_ok)} ({str(100 * nflog_ok / nflogall)[0:5]} %);" \
                      f"Capacity in being compressed for download (10M-10G):{str(tar_log)} （{str(100 * tar_log / nflogall)[0:5]} %);" \
                      f"\nOver capacity not downloaded(>10G)：{str(nodown_log)} ({str(100 * nodown_log / nflogall)[0:5]} %);" \
                      f"Duplicates detected but not downloaded: {redown} ({str(100 * redown / nflogall)[0:5]} %);" \
                      f"\nError: {str(nflog_err)} ({str(100 * nflog_err / nflogall)[0:5]} %).\n"
            print("The remote LOG has been analyzed and processed.")
            # print(msg_3_3)
        else:
            msg_3_3 = "The LOG file of the POC is not generated in the remote server yet."
        sum_path = join(Root_path, Log_root_path, log_rfolder_name).replace("\\", "/") + "/"
        sum_filename = (f"sum_poc_getlog_{time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime())}" + ".log").replace(
            "\r\n", "")
        with open(sum_path + sum_filename, "w+") as sfse:
            sfse.write(
                f"---Current POC statistics for remote download of LOG --- \n --- current time {time.asctime()}---\n")
            sfse.write(msg_3_3)
        # print(msg_3_3)
        return msg_3_3

    def Close(self):
        self.ssh.close()
        self.sftp.close()


def Labserver_adddb():
    labserver_db_name = "kernel_trace_dstserver"
    labserver_srclog = "labserverinfo_input.txt"
    labserver_info_listall = []  # List of all test server data, one server per element
    labser_info_path = join(Root_path, Log_root_path)
    ex_path = labser_info_path + labserver_srclog
    if os.path.exists(ex_path):
        with open(ex_path, "r") as fsin:
            info_list = list(filter(None, fsin.read().split("@\n")))
            if len(info_list) < 1:  # Exit if there is no configuration information in the file
                exit()
            # print(info_list)
            for info in info_list:
                info_k = list(filter(None, info.split("\n")))
                labserver_info_list = []  # Single server dictionary, 9 elements
                for info_s in info_k:
                    info_s = info_s.replace(":", "：")
                    info_sp = info_s.split("：")
                    labserver_info_list.append(info_sp[1])
                    # print(info_sp[1])
                if labserver_info_list not in labserver_info_listall:
                    labserver_info_listall.append(labserver_info_list)
            # print(labserver_info_listall)

        # write db
        pzi = oki = 0
        if len(labserver_info_listall) > 1:
            find_redo = mydb[labserver_db_name]
            for server_list_sub in labserver_info_listall:
                cp = find_redo.count_documents({"ktd_server_ip": server_list_sub[1],
                                                "ktd_server_ssh_port": server_list_sub[5],
                                                "ktd_server_kernel_ver": server_list_sub[6]})
                lot_p = find_redo.count_documents({"ktd_info_lot": server_list_sub[9]})
                if cp > 0:
                    print(f"Duplicate, this server is already in the library, please clear and rewrite. "
                          f"IP: {server_list_sub[1]}，Port: {server_list_sub[5]}，"
                          f"K-Ver: {server_list_sub[6]}")
                    continue
                elif lot_p > 0:
                    print(f"Repeat, a single batch of servers in the library must not be repeated, "
                          f"please re-write after planning. IP: {server_list_sub[1]}，Port: {server_list_sub[5]}，"
                          f"K-Ver: {server_list_sub[6]}, Lot: {server_list_sub[9]}")
                    continue
                else:
                    pzi += 1

                    ktd_info_lot = server_list_sub[9]
                    ktd_info_partin = True
                    ktd_info_contents = ""
                    server_list = [{"ktd_server_name": server_list_sub[0],
                                    "ktd_server_ip": server_list_sub[1],
                                    "ktd_server_username": server_list_sub[2],
                                    "ktd_server_userpwd": server_list_sub[3],
                                    "ktd_server_rootpwd": server_list_sub[4],
                                    "ktd_server_ssh_port": server_list_sub[5],
                                    "ktd_server_kernel_ver": server_list_sub[6],
                                    "ktd_labtool_name": server_list_sub[7],
                                    "ktd_labtool_method": server_list_sub[8],
                                    "ktd_info_time": time.asctime(),
                                    "ktd_info_lot": ktd_info_lot,
                                    "ktd_info_partin": ktd_info_partin,
                                    "ktd_info_complete": False,
                                    "ktd_info_completetime": "",
                                    "ktd_esxi_host_name": server_list_sub[10],
                                    "ktd_esxi_ip": server_list_sub[11],
                                    "ktd_esxi_username": server_list_sub[12],
                                    "ktd_esxi_pwd": server_list_sub[13],
                                    "ktd_esxi_port": server_list_sub[14],
                                    "ktd_expend_time": 0,
                                    "ktd_info_contents": ktd_info_contents
                                    }]
                    listwrite(labserver_db_name, server_list)
                    oki += 1
                    print(f"---Successfully added the experimental server {str(pzi)} ---")
            ser_add_msg = "The new server addition is complete!"
    else:
        ser_add_msg = f"In the {Log_root_path} directory, the experiment server initialization " \
                      f"information file {labserver_srclog} was not found."
    # print(ser_add_msg)
    return ser_add_msg


def Vm_reboot(serverid):
    print(f"Restart server ID：{serverid}")
    vmreboot_state = False
    vmreboot_mem = True
    vmreboot_msg = ""
    vm_hostname = ""
    test_on_times = 0  # test times
    vm_host_list = []
    check_server_col = mydb["kernel_trace_dstserver"].find_one({"_id": ObjectId(f"{serverid}")})
    e_ip, e_user, e_pwd, e_port = check_server_col["ktd_esxi_ip"], check_server_col["ktd_esxi_username"], \
                                  check_server_col["ktd_esxi_pwd"], int(check_server_col["ktd_esxi_port"])
    try:
        if all([e_ip, e_user, e_pwd, e_port]):
            vm_hostname = check_server_col["ktd_esxi_host_name"]
            vm_esxi = VM_esxi_state(e_ip, e_user, e_pwd, e_port, None)
            vm_host_list = vm_esxi.get_name_vm()
            if vm_hostname in vm_host_list:
                if vm_esxi.get_status_vm(f"{vm_hostname}")["vm_powerstate"] == "poweredOn":
                    print(vm_esxi.poweroff_vm(f"{vm_hostname}"))
                    time.sleep(2)
                if vm_esxi.get_status_vm(f"{vm_hostname}")["vm_powerstate"] == "poweredOff":
                    print(vm_esxi.poweron_vm(f"{vm_hostname}"))
                    time.sleep(2)
            else:
                vmreboot_mem = False
                vmreboot_msg = f"VM: {vm_hostname} in the library is not in the ESXI host list: {vm_host_list}."

            for test_on_i in range(0, 60):
                test_on_times += 1
                try:
                    sshtest_on = ssh_test_single(check_server_col["ktd_server_ip"],
                                                 check_server_col["ktd_server_username"],
                                                 check_server_col["ktd_server_userpwd"],
                                                 check_server_col["ktd_server_ssh_port"])
                    if sshtest_on == True or sshtest_on == "true":
                        vmreboot_state = True
                        print("The server under test restarted successfully.")
                        break
                    else:
                        continue
                except Exception as retest_error:
                    time.sleep(5)
                    print(f"{test_on_times}.{retest_error}...", end="")
                    print("") if test_on_times % 10 == 0 else print("", end="")
            if test_on_times > 1:
                print("")  # No line break before the end
        else:
            vmreboot_mem = False
            vmreboot_msg = f"Failed to read ESXI host list, please check ESXI server cluster."
    except Exception as reset_error:
        vmreboot_state = False
        vmreboot_msg = f"Failed to restart VM, Err:{repr(reset_error)}\r\n"

    # If it returns True, the startup is successful. If there is no such VM in the False library,
    # if there is an error, the while loop will be executed until the result is obtained normally.
    while True:
        global vmre_times
        endtimes = 5
        vmre_times += 1
        # 定The definition is overtime, the VM startup is True to exit, and the LOOP test is tentatively set to 5 times.
        if (vmreboot_mem == False) or (vmreboot_state == True) or (vmre_times > endtimes):
            break
        if endtimes < 5:
            print(f"Restart {vmre_times}th")
        else:
            print(f"Esxi server cannot be connected, it may be a network failure, please check.")
        vmreboot_state = Vm_reboot(serverid)
    # print(f"vmreboot_msg:{vmreboot_msg}")
    return vmreboot_state


def Analysis_working(work_cls, labserverid, lots):
    alabserver_db_name = "kernel_trace_dstserver"
    aser_mycol = mydb[alabserver_db_name].find_one({"_id": ObjectId(f"{labserverid}")})
    stats = aser_mycol["ktd_info_complete"]
    sim_labserver_id = aser_mycol["_id"]

    aip = aser_mycol["ktd_server_ip"]
    aport = int(aser_mycol["ktd_server_ssh_port"])
    in_workversion = aser_mycol["ktd_server_kernel_ver"]
    out_info_working, dstserver_version, sshconn = "", "", ""

    try:
        sshconn = SSH(sim_labserver_id, work_cls)  # Calling Work Classes
        # sshconn = SSH(ip, user, pwd, rpwd, port, tool_name, tool_method)  # Calling Work Classes
        dstserver_version_src = sshconn._exec_command("uname -r").replace("\r\n", "")
        dstserver_version_mem = dstserver_version_src.split("-", 1)[0].split(".")
        # dstserver_version = dstserver_version_mem[0] + "." + dstserver_version_mem[1] + "." + dstserver_version_mem[2]
        dstserver_version = dstserver_version_mem[0] + "." + dstserver_version_mem[1]
        print(f"-Conn ssh server is ok,Remote Server Kernel Version:{dstserver_version_src}.-")
    except Exception as master_ssherror:
        print(f"Error0：SSH Master Error,{repr(master_ssherror)}")
        print(f"Program initialization error, please check the server.")
        Analysis_main(work_cls, labserverid, lots)

    if dstserver_version == in_workversion:
        labserver_info = "kernel_trace_dstserver"
        mod_mycol = mydb[labserver_info]
        try:
            if work_cls == "Working" and stats != "Working":
                out_info_working = sshconn.Exec_working(in_workversion)
                mod_mycol.update_one({"ktd_server_ip": f"{aip}", "ktd_server_ssh_port": f"{aport}",
                                      "ktd_server_kernel_ver": f"{in_workversion}"}, {
                                         "$set": {"ktd_info_complete": "Working"}})
            elif work_cls == "Killpids" and stats != "Killpids":
                out_info_working = sshconn.Exec_Killpid()
                mod_mycol.update_one({"ktd_server_ip": f"{aip}", "ktd_server_ssh_port": f"{aport}",
                                      "ktd_server_kernel_ver": f"{in_workversion}"}, {
                                         "$set": {"ktd_info_complete": "Killpids"}})
            elif work_cls == "Getlogfiles" and stats != "Getlogfiles":
                out_info_working = sshconn.Exec_getlog()
                mod_mycol.update_one({"ktd_server_ip": f"{aip}", "ktd_server_ssh_port": f"{aport}",
                                      "ktd_server_kernel_ver": f"{in_workversion}"}, {
                                         "$set": {"ktd_info_complete": "Getlogfiles"}})
            elif work_cls == "All":
                print("The following is a comprehensive collection of POC's Syscall from "
                      "upload data analysis -> process wait and shutdown -> remote data download."
                      "\n======Session 1 Upload data and analyze======")
                msg_3_1 = sshconn.Exec_working(in_workversion)
                mod_mycol.update_one({"ktd_server_ip": f"{aip}", "ktd_server_ssh_port": f"{aport}",
                                      "ktd_server_kernel_ver": f"{in_workversion}"}, {
                                         "$set": {"ktd_info_complete": "Working"}})

                print("======Session 2 Process Waiting and Closing======")
                ewait_time = 3
                print(f"tips: Wait for the remote POC execution to complete, where it will wait for {ewait_time} s...")
                time.sleep(0.01)
                for pb in tqdm(range(0, ewait_time), desc="Wait Completed (S)"):
                    time.sleep(1)
                time.sleep(0.01)
                msg_3_2 = sshconn.Exec_Killpid()
                mod_mycol.update_one({"ktd_server_ip": f"{aip}", "ktd_server_ssh_port": f"{aport}",
                                      "ktd_server_kernel_ver": f"{in_workversion}"}, {
                                         "$set": {"ktd_info_complete": "Killpids"}})

                print(f"======Session 3 Remote Data Download======")
                msg_3_3 = sshconn.Exec_getlog()
                mod_mycol.update_one({"ktd_server_ip": f"{aip}", "ktd_server_ssh_port": f"{aport}",
                                      "ktd_server_kernel_ver": f"{in_workversion}"}, {
                                         "$set": {"ktd_info_complete": "true",
                                                  "ktd_info_completetime": f"{time.asctime()}"}})

                msg_3_0 = "\n======By running the POC remotely to get Syzcall or Hook, the whole " \
                          "process is automated and completed with the following results. ======\n"

                out_info_working = msg_3_0 + msg_3_1 + msg_3_2 + msg_3_3
                sum_path = join(Root_path, Log_root_path).replace("\\", "/") + "/"
                sum_filename = ("sum_poc_all_" + sshconn._new_folder(
                    "rkversion") + f"{time.strftime('%Y-%m-%d_%H-%M-%S', time.localtime())}" + ".log").replace("\r\n",
                                                                                                               "")
                with open(sum_path + sum_filename, "w+") as endfs:
                    endfs.write(
                        "======Syzcall is obtained by running the POC remotely, and the entire process is automated.======\n")
                    endfs.write("The following will be a comprehensive collection of POC Syscall from: Upload Data "
                                "Analysis -> Process Waiting and Closing -> Remote Data Download.\n\n"
                                "======Session 1 Upload data and analyze======\n")
                    endfs.write(msg_3_1)
                    endfs.write("\n\n======Session 2 Process Waiting and Closing======\n")
                    endfs.write(msg_3_2)
                    endfs.write("\n\n======Session 3 Remote Data Download======\n")
                    endfs.write(msg_3_3)

            else:
                if stats == "":
                    out_info_working = "Error1：The incoming POC tracking action was incorrectly classified."
        except Exception as error_msg:
            out_info_working = f"Error2：POC tracking error: {error_msg}"
            Analysis_main(work_cls, sim_labserver_id, lots)
        finally:
            mod_mycol.close()
    else:
        out_info_working = "Error3：Version inconsistency, specifying that the working kernel " \
                           "version is different from the target server version"
    sshconn.Close()
    # print(out_info_working)
    return out_info_working


def Gather_one(work_cls, server_id, lots, begin_i):  # Single experiment server work
    g_msg = ""
    glabserver_db_name = "kernel_trace_dstserver"
    gser_mycol = mydb[glabserver_db_name].find_one({"_id": ObjectId(f"{server_id}")})
    sim_labserver_id = gser_mycol["_id"]
    vm_stats = gser_mycol["ktd_info_complete"]

    if vm_stats == "true" or vm_stats == True:
        loop_state = False
        g_msg = f"The current server status is {vm_stats} and this phase is complete.\r" \
                f"The current server data has been collected. Socket: {gser_mycol['ktd_server_ip']}:{gser_mycol['ktd_server_ssh_port']}，" \
                f"Kver:{gser_mycol['ktd_server_kernel_ver']}。"
    else:
        try:
            if (gser_mycol["ktd_info_partin"] == True) and (gser_mycol["ktd_info_complete"] != "true" or
                                                            gser_mycol["ktd_info_complete"] != True) and \
                    (gser_mycol["ktd_info_lot"] == lots):
                wver = gser_mycol["ktd_server_kernel_ver"]
                ip = gser_mycol["ktd_server_ip"]
                port = gser_mycol["ktd_server_ssh_port"]
                print(
                    f"Automated Working ... The {lots} batch, the {begin_i} server. Socket: {ip}:{port}，Kver in DB:{wver}。")
                w_msg = Analysis_working(work_cls, sim_labserver_id, lots)
                loop_state = False
                g_msg = w_msg + f"\nSocket: {ip}:{port}，Kver:{wver} Server POC Strace processing is complete.\r\n\n"

        except Exception as gather_error:
            if vm_stats == "Working" or vm_stats == "Killpids" or vm_stats == "Getlogfiles":
                g_msg = f"The current server status is {gser_mycol['ktd_info_complete']} and this phase is complete.\r\n"
                loop_state = False
            else:
                loop_state = True
                g_msg = f"Server connection failed. Time({datetime.datetime.now().strftime('%m-%d %H:%M:%S')})。" + repr(
                    gather_error)
    return loop_state, g_msg


def Analysis_main(work_cls, labserver, lot):
    start_time = time.time()
    print("---AIM Kernel POC Automated Trace and analysis Program is Working---")

    lotin = lot if lot != "" else 1
    lots = str(lotin)
    alllabserver, okti, succ_i, noi = 0, 0, 0, 0
    sim_labserver_id, expend_time, out_info_main, labserver_add_msg = "", "", "", ""
    ats_state, work_state = "", ""
    begin_i = 0
    labserver_add = False

    if labserver == "add":
        labserver_add_msg = Labserver_adddb()
        labserver_add = True
    else:
        labserver_db_name = "kernel_trace_dstserver"
        cursor_server_list = []
        ser_mycol = mydb[labserver_db_name].find({}, {"_id": 1, "ktd_server_name": 1, "ktd_server_ip": 1,
                                                      "ktd_server_username": 1, "ktd_server_userpwd": 1,
                                                      "ktd_server_rootpwd": 1, "ktd_server_ssh_port": 1,
                                                      "ktd_server_kernel_ver": 1, "ktd_labtool_name": 1,
                                                      "ktd_labtool_method": 1, "ktd_info_time": 1,
                                                      "ktd_info_lot": 1, "ktd_info_partin": 1,
                                                      "ktd_info_complete": 1})
        for cursor_server_men in ser_mycol:
            cursor_server_list.append(cursor_server_men)
        ser_mycol.close()

        alllabserver = mydb[labserver_db_name].count_documents(
            {"ktd_info_partin": True, "ktd_info_lot": f"{lots}"})
        okti = mydb[labserver_db_name].count_documents(
            {"ktd_info_partin": True, "ktd_info_lot": f"{lots}", "ktd_info_complete": {"$ne": False}})

        if len(cursor_server_list) < 1:
            print("There is no server IP information in the library for the experiment, "
                  "and the server adding process will be started soon.")
            labserver_add_msg = Labserver_adddb()
            labserver_add = True
        try:
            # Fetch the incoming batch server from the server list, without its status
            for server_siminfo in cursor_server_list:
                if server_siminfo[
                    "ktd_info_lot"] != lots:  # Experimental servers that are not part of this batch do not participate in the work
                    continue
                sim_labserver_id = server_siminfo["_id"]
                begin_i += 1
                # print([work_cls, sim_labserver_id, lots, begin_i])
                ats_state = ssh_test_single(server_siminfo["ktd_server_ip"],
                                            server_siminfo["ktd_server_username"],
                                            server_siminfo["ktd_server_userpwd"],
                                            server_siminfo["ktd_server_ssh_port"])
                # If the server status is True, the current one is scheduled to work. Otherwise, restart
                if ats_state == True or ats_state == "true":
                    succ_i += 1
                    Gather_ru = Gather_one(work_cls, sim_labserver_id, lots, begin_i)
                    out_info_main = f"Info1-1：{Gather_ru}"
                else:
                    work_state = False
                    noi += 1  # Batch is used when more than one, temporarily defined as one
                    raise
            work_state = True
        except Exception as main_error:
            out_info_main = f"Error1, server SSH connection status: {main_error}"
            work_state = False
            while True:
                global re_times
                re_times += 1
                server_ru = Vm_reboot(sim_labserver_id)
                # The definition is overtime, the VM startup is True to exit, and the LOOP test is tentatively set to 5 times.
                if (server_ru == True) or (re_times > 50):
                    # if (server_ru == True) or (re_times > 5) or (check_dhserver_state == work_cls):
                    break
                print(f"---Error-end: This Strace test failed, restart the test program for the first {re_times} "
                      f"time... If you need to stop immediately, please kill the process."
                      f"Time({datetime.datetime.now().strftime('%m-%d %H:%M:%S')})---")
            # After a successful start, continue working from the beginning
            if server_ru == True or server_ru == "true":
                Analysis_main(work_cls, labserver, lots)

        end_time = time.time()
        expend_time = format((end_time - start_time), ".2f")
        # print(sim_labserver_id)
        if work_cls == "All" and work_state == True:
            modpoc_mycol = mydb[labserver_db_name].update_one(
                {"_id": ObjectId(f"{sim_labserver_id}"), "ktd_info_lot": lots},
                {"$set": {"ktd_expend_time": f"{expend_time}"}})

    serwork_msg = f"After successfully executing the {lots} batch of experiments (total {alllabserver} " \
                  f"units in this batch), the result of this check: the status is 'Current job OK' {okti} units." \
                  f"Successfully run {succ_i}, unable to connect {str(noi)}, SSH connection retries {re_times}.\n" \
                  f"This batch of experiments consumed a total of (Data-A0204) {expend_time} seconds." \
                  f"Marker POC：{len(list(Ept_dict))}."
    if work_state == True:
        print(serwork_msg)
    else:
        if labserver_add == True:
            print(labserver_add_msg)
        else:
            print(f"Error in initialization, {out_info_main}, please initialize again.")


if __name__ == '__main__':
    # testing
    lot = "10"
    # Analysis_main("Working", "stopadd", lot)
    # Analysis_main("Killpids", "stopadd", lot)
    # Analysis_main("Getlogfiles", "stopadd", lot)
    Analysis_main("All", "stopadd", lot)
