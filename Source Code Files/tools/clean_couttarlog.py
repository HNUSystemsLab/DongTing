
import paramiko
import time

def clear_data(ip, user, pwd, port,command):
    ssht = paramiko.SSHClient()
    ssht.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssht.connect(ip, username=user, port=port, password=pwd, timeout=10, banner_timeout=60, allow_agent=False,
                 look_for_keys=False)
    # command = "ls -l"
    ssh_stdin, ssh_stdout, ssh_stderr = ssht.exec_command(command, get_pty=True)
    time.sleep(5)
    out_msg = ssh_stdout.read().decode()
    # print(out_msg)
    return out_msg


if __name__ == '__main__':
    ip = "115.157.201.227"
    user = "aimadmin"
    pwd = "aef34grssad"
    port = 22

    command1 = "ls -l"
    ru = clear_data(ip, user, pwd, port,command1)
    print(ru)

    command1 = f"rm -rf *.log *.c *.out *.tar *.xz;echo {pwd} | sudo -S rm -rf syzkaller*"
    ru = clear_data(ip, user, pwd, port, command1)
    print(ru)
    print("Clear Data OK")
