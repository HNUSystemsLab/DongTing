import paramiko
import time
from paramiko.ssh_exception import SSHException

'''
VM connection test program
'''

def ssh_testing(inip, inuser, inpwd, inport):
    ip, user, pwd, port = inip, inuser, inpwd, int(inport)
    end_msg = ""
    out_msg = ""
    state = False
    try:
        if all([ip, user, pwd, port]):
            ssht = paramiko.SSHClient()
            ssht.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Allow connections to hosts that are not in the know_hosts file
            # ssh.connect(ip, username=user, port=port, password=pwd, timeout=10, banner_timeout=300)
            # try:
            ssht.connect(ip, username=user, port=port, password=pwd, timeout=10, banner_timeout=60, allow_agent=False,
                         look_for_keys=False)
            command = "ls -l;ps -a"
            ssh_stdin, ssh_stdout, ssh_stderr = ssht.exec_command(command, get_pty=True)
            time.sleep(2)
            out_msg = ssh_stdout.read().decode()
            if len(out_msg) > 5:
                state = True
            else:
                state = False
            # ssht.close()
    except Exception as sshtest_error:
        state = False
        out_msg = f"SSH_testing, the connection failed. Details: {repr(sshtest_error)}"
        # print(f"Errore:{repr(e)}")

    end_msg = out_msg
    return state, end_msg


def ssh_test_single(ip, user, pwd, port):
    out_state = False
    ssht = paramiko.SSHClient()
    ssht.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Allow connections to hosts that are not in the know_hosts file
    ssht.connect(ip, username=user, port=port, password=pwd, timeout=10, banner_timeout=60, allow_agent=False,
                 look_for_keys=False)
    command = "ps -a"
    ssh_stdin, ssh_stdout, ssh_stderr = ssht.exec_command(command, get_pty=True)


    out_msg = ssh_stdout.read().decode()
    ssht.close()
    if len(out_msg) > 5:
        out_state = True
    else:
        out_state = False
    # print(out_msg)
    return out_state


if __name__ == '__main__':
    ip = "115.157.201.202"
    user = "aimadmin"
    pwd = "efeadg"
    port = 22
    ru = ssh_test_single(ip, user, pwd, port)
    # print(ru[0])
    # print(ru[1])
    print(ru)
