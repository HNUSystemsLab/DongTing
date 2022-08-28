import atexit
import ssl
from pyvim import connect
from pyVmomi import vmodl, vim

'''
This program mainly completes VM monitoring, switching on/off, and VM kernel version switching. Instructions for use.
1、This program is suitable for windows/linux operating system as data operation terminal, remote for ubuntu system environment.
2、After connecting to the server, the working folder will be the current user's login folder.
'''


# VM Status Monitoring
class VM_esxi_state():
    def __init__(self, ip, user, pwd, port, context):
        self.ip, self.user, self.pwd, self.port = ip, user, pwd, int(port)

        if hasattr(ssl, "_create_unverified_context"):
            context = ssl._create_unverified_context()
        # self.conn_esxi = connect.SmartConnect(host=ip, user=user, pwd=pwd, port=port, sslContext=context)
        self.conn_esxi = connect.SmartConnectNoSSL(host=ip, user=user, pwd=pwd, port=port)
        if not self.conn_esxi:
            print("The ESXI username and password are incorrect, please try again.")
        atexit.register(connect.Disconnect, self.conn_esxi)
        self.content = self.conn_esxi.RetrieveContent()

    def exec_tasks(self, tasks): # task
        pc = self.conn_esxi.content.propertyCollector
        taskList = [str(task) for task in tasks]
        objSpecs = [vmodl.query.PropertyCollector.ObjectSpec(obj=task) for task in tasks]
        propSpec = vmodl.query.PropertyCollector.PropertySpec(type=vim.Task, pathSet=[], all=True)
        filterSpec = vmodl.query.PropertyCollector.FilterSpec()
        filterSpec.objectSet = objSpecs
        filterSpec.propSet = [propSpec]
        filter = pc.CreateFilter(filterSpec, True)
        try:
            version, state = None, None
            while len(taskList):
                update = pc.WaitForUpdates(version)
                for filterSet in update.filterSet:
                    for objSet in filterSet.objectSet:
                        task = objSet.obj
                        for change in objSet.changeSet:
                            if change.name == 'info':
                                state = change.val.state
                            elif change.name == 'info.state':
                                state = change.val
                            else:
                                continue
                            if not str(task) in taskList:
                                continue
                            if state == vim.TaskInfo.State.success:
                                taskList.remove(str(task))
                            elif state == vim.TaskInfo.State.error:
                                raise task.info.error
                version = update.version
        finally:
            if filter:
                filter.Destroy()

    def get_name_vm(self):  # Get VM list, print all VM names
        vmname_list = []
        for child in self.content.rootFolder.childEntity:
            if hasattr(child, 'vmFolder'):
                vmlists = child.vmFolder.childEntity
                for vm in vmlists:
                    if vm.summary.config.name not in vmname_list:
                        vmname_list.append(vm.summary.config.name)
        return vmname_list

    def get_status_vm(self, vm_name):  # Get specified VM information and status
        vmstats_dict = {}
        for child in self.content.rootFolder.childEntity:
            if hasattr(child, 'vmFolder'):
                vmLists = child.vmFolder.childEntity
                for vm in vmLists:
                    if vm.summary.config.name == vm_name:
                        vmstats_dict["vm_name"] = vm.name
                        vmstats_dict["vm_powerstate"] = vm.summary.runtime.powerState
        return vmstats_dict

    def poweron_vm(self, vm_name):  # Turn on a VM
        objView = self.content.viewManager.CreateContainerView(self.content.rootFolder, [vim.VirtualMachine], True)
        vmList = objView.view
        objView.Destroy()
        tasks = [vm.PowerOn() for vm in vmList if vm.name in vm_name]
        # print(tasks)
        self.exec_tasks(tasks)
        msg = f"VM：{vm_name} PowerOn is ok"
        return msg

    def poweroff_vm(self, vm_name):  # Turn off a VM
        objView = self.content.viewManager.CreateContainerView(self.content.rootFolder, [vim.VirtualMachine], True)
        vmList = objView.view
        objView.Destroy()
        tasks = [vm.PowerOff() for vm in vmList if vm.name in vm_name]
        # print(tasks)
        self.exec_tasks(tasks)
        msg = f"VM：{vm_name} PowerOff is ok"
        return msg


def Working_state():
    vsphere_ip = "115.157.201.252"
    vsphere_user = "root"
    vsphere_pwd = "er3ghfgm"
    vsphere_port = 443
    vsphere_context = None
    conn = VM_esxi_state(vsphere_ip, vsphere_user, vsphere_pwd, vsphere_port, vsphere_context)

    print(conn.get_name_vm())
    print(conn.get_status_vm("lab-202"))

    if conn.get_status_vm("lab-202")["vm_powerstate"] == "poweredOn":
        print(conn.poweroff_vm("lab-202"))


# testing
if __name__ == '__main__':
    Working_state()
