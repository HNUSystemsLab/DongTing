import re

import paramiko
import time

'''
Handle executable programs that take longer than 20 minutes to execute
'''


def clear_data(ip, user, pwd, port, command):
    ssht = paramiko.SSHClient()
    ssht.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssht.connect(ip, username=user, port=port, password=pwd, timeout=10, banner_timeout=60, allow_agent=False,
                 look_for_keys=False)
    # command = "ls -l"
    ssh_stdin, ssh_stdout, ssh_stderr = ssht.exec_command(command, get_pty=True)
    time.sleep(1)
    out_msg = ssh_stdout.read().decode()
    # print(out_msg)
    return out_msg


def split_time(msg, rpwd):
    ps_out_lines = msg.split("\r\n")
    pro_com, out_msg = "", ""
    for ps_out_mem in ps_out_lines:
        ps_out_list = list(filter(None, ps_out_mem.split(" ")))
        # print(ps_out_list)
        if len(ps_out_list) < 2:
            continue
        else:
            pro_time = ps_out_list[1].split(":")[0]
            print(f"PID:{ps_out_list[0]},TIME:{int(pro_time)}")
            if int(pro_time) > 19:  # Checking for more than 20 minutes, automatically clears the
                print(f"Kill process {ps_out_list[0]}")
                pro_com = f"echo {rpwd} | sudo -S kill -9 {int(ps_out_list[0])}"
                out_msg = pro_com
            else:
                out_msg = ps_out_list
        # ps_out_line = re.sub(" ", "", ps_out_mem)
        print(out_msg)
    return pro_com, len(ps_out_lines), out_msg


def loop_full(ip, user, pwd, port):
    i = 0
    while True:
        try:
            i += 1
            command1 = f"ps -eo pid,etime,cmd | grep strace"
            ru_out = clear_data(ip, user, pwd, port, command1)
            print(f"Times:{i}")
            sp_time = split_time(ru_out, pwd)
            # ru = sp_time[0]
            clear_data(ip, user, pwd, port, sp_time[0])
            if int(sp_time[1]) < 3:
                break
        except:
            loop_full(ip, user, pwd, port)


if __name__ == '__main__':
    ip = "115.157.201.227"
    user = "aimadmin"
    pwd = "dfae54gresm"
    port = 22

    loop_full(ip, user, pwd, port)
