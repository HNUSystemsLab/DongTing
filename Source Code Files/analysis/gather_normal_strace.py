import pathlib

import paramiko
import eventlet

from conn.dbconn import *
import os
from os.path import join
import time
import datetime
from tqdm import tqdm
from bson.objectid import ObjectId
from public.pub_network_test import *
from public.pub_fun_analysis import *

Root_path = os.path.abspath(os.path.dirname(__file__))
# print(Root_path)
normal_log_root_path = "normal_log" + "\\"


# dirname_list = ["ltp", "kselftest", "posixtest"]

def Repeat_file_check(filename,logpathcls):  # Same name file detection, can detect one or more at a time,
    # when multiple, multiple files are separated by
    linestr = filename.split(",") if filename.split(",") else [filename]
    # print(linestr)
    filelists = []
    if filename != "":
        r_path = join(Root_path, normal_log_root_path, logpathcls)
        for parent, dirnames, filenames in os.walk(r_path):
            for filename in filenames:
                filelists.append(filename.split(".")[0])
    return True if any(i in linestr for i in filelists) else False


class SSH():

    def __init__(self, ip, user, pwd, rpwd, port):
        self.ip, self.user, self.pwd, self.rpwd, self.port = ip, user, pwd, rpwd, int(port)
        self.timeout = 10
        self.bannertimeout = 200

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(
            paramiko.AutoAddPolicy())  # Allow connections to hosts that are not in the know_hosts file
        self.ssh.connect(self.ip, username=self.user, port=self.port, password=self.pwd,
                         timeout=self.timeout)  # Establish ssh connection

    def _exec_command(self, in_command):  # Command Execution Procedures
        # self._conn_server()
        command = in_command
        ssh_stdin, ssh_stdout, ssh_stderr = self.ssh.exec_command(command,
                                                                  get_pty=True)  # Use this connection to execute the command
        time.sleep(1)
        r_msg = ssh_stdout.read().decode()
        return r_msg

    def _test_rpath(self):
        rpath_command = "pwd"  # Query the current directory as the root directory for storing results
        remote_path = self._exec_command(rpath_command)
        remotepath = remote_path.strip()
        # print(remotepath)
        return remotepath  # /home/username

    def exec_working(self, dirPath):
        dirname_list = ["ltp", "kselftest", "posixtest", "kselftest"]
        # dirname_list = ["ltp"]
        gl_sftpc = self.ssh.open_sftp()
        # The collection of programs that take more than five minutes to execute in the four major data sets,
        # please change as needed when executing the program
        ltp_check_keys = ["fork_exec_loop", "msgstress04", "pec_listener", "vfork", "memcg_test_2",
                          "cgroup_regression_fork_processes", "timed_forkbomb", "tirpc_rpc_broadcast_exp_complex",
                          "cpuset_memory_test", "tomoyo_policy_memory_test","cpuset_mem_hog", "shm_test",
                          "cpuctl_fj_cpu-hog", "rpc_server", "mmap3", "fork12", "oom01", "memcg_test_4",
                          "setsockopt09", "cgroup_fj_proc","cgroup_regression_6_2", "fanout01", "min_free_kbytes",
                          "pids_task2", "writev03", "tirpc_rpc_broadcast_exp", "cpuset_cpu_hog", "proc01",
                          "cpuhotplug_do_spin_loop", "cpuhotplug_do_disk_write_loop", "msgstress03"]
        posix_check_keys = ["11-1.test", "timer_getoverrun2-3.test", "pthread_barrier_destroy2-1.test", "9-1.test",
                            "10-1.test", "clock1-1.test", "pidns05"]
        kselftest_check_keys = ["proc-pid-vm", "alarmtimer-suspend"]
        # The set of all file names in the four datasets that take too long to execute
        check_keys = ["fork_exec_loop", "msgstress04", "pec_listener", "vfork", "memcg_test_2", "11-1.test",
                      "timer_getoverrun2-3.test", "pthread_barrier_destroy2-1.test", "9-1.test", "10-1.test",
                      "clock1-1.test", "proc-pid-vm", "alarmtimer-suspend", "pidns05", "cgroup_regression_fork_processes",
                      "timed_forkbomb","tirpc_rpc_broadcast_exp_complex","cpuset_memory_test",
                      "tomoyo_policy_memory_test", "cpuset_mem_hog", "shm_test","cpuctl_fj_cpu-hog", "rpc_server",
                      "mmap3", "fork12", "oom01", "memcg_test_4", "setsockopt09", "cgroup_fj_proc",
                      "cgroup_regression_6_2", "fanout01", "min_free_kbytes","pids_task2", "writev03",
                      "tirpc_rpc_broadcast_exp", "cpuset_cpu_hog", "proc01", "cpuhotplug_do_spin_loop",
                      "cpuhotplug_do_disk_write_loop", "msgstress03"]
        # print(gl_rfiles)
        count = 0
        compled_file_list = []

        for dirname in dirname_list:
            gl_rfiles_test = gl_sftpc.listdir(f"test/{dirname}")
            info_list = list(filter(None, gl_rfiles_test))
            mkdir_command = f"mkdir ~/log_dir/{dirname}"
            mkdir_info = self._exec_command(mkdir_command)
            local_dir = f"{dirname}"
            self.sftp_trans = paramiko.Transport(sock=(self.ip, self.port))
            self.sftp_trans.connect(username=self.user, password=self.pwd)
            self.sftp_trans.set_keepalive(60)  # To prevent timeout, turn on the heartbeat packet function.
            self.sftp_trans.banner_timeout = 300  # Optional timeout (in seconds) to wait for SSH banner to appear
            self.sftp = paramiko.SFTPClient.from_transport(self.sftp_trans)
            remote_dir_path = f"/home/aimadmin/log_dir/{dirname}"
            local_dir_path = "normal_log" + "/" + f"{dirname}"
            pathlib.Path(local_dir_path).mkdir(parents=True, exist_ok=True)
            gl_sftpc = self.ssh.open_sftp()

            for executeFile in info_list:
                # print(executeFile)
                # print(local_dir)
                if Repeat_file_check(executeFile, local_dir):
                    print(f"{executeFile}" + "This article has been executed and has duplicate information, "
                                             "this execution process is omitted.")
                    continue
                if not contain_str(executeFile, check_keys):
                    compled_file_list.append(executeFile)
                    print(compled_file_list)
                    start_time = time.time()
                    count = count + 1
                    current_command = f"cd test/{dirname} ;echo {self.rpwd} | sudo -S nohup strace -v -f " \
                                      f"./{executeFile} > ~/log_dir/{dirname}/{executeFile}.log"
                    info = self._exec_command(current_command)
                    print(f"this command has been completed {count}")
                    print(executeFile)
                    completed_time = time.time()
                    print(str(completed_time - start_time))
                    remote_file_path = remote_dir_path + "/" + executeFile + ".log"
                    local_file_path = local_dir_path + "/" + executeFile + ".log"
                    # print(remote_file_path)
                    # print(local_file_path)
                    self.sftp.get(remote_file_path, local_file_path)
                    print(f"{executeFile}" + "Downloaded")

    def Close(self):
        self.ssh.close()


def Analysis_working(inip, inuser, inpwd, inrpwd, inport):
    ip, user, pwd, rpwd, port = inip, inuser, inpwd, inrpwd, int(inport)

    sshconn = SSH(ip, user, pwd, rpwd, port)
    print("*** The Normal strace log Automated analysis program is working. ***\n*** Conn ssh server is ok. ***")
    ltp_path = "/home/aimadmin/test/"
    sshconn.exec_working(ltp_path)
    # sshconn.test_rpath()

    sshconn.Close()

# testing
if __name__ == '__main__':
    ip = "115.157.201.252"
    user = "aimadmin"
    pwd = "sfe23dggm"
    rpwd = pwd
    port = 22
    Analysis_working(ip, user, pwd, rpwd, port)
