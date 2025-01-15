# 创建者：Kenneth1004
# 创建时间：2024.12.15
# 最后编辑：2024.12.31
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, font
from ttkthemes import *  # 美化 tkinter
from pysnmp.hlapi import *  # pysnmp 4.4.12
import ipaddress  # 判断 IP 地址

class MIBTreeBrowser:
    def __init__(self, root):
        self.root = root
        self.root.title("MIB Tree Browser中文版")

        # 输入字段 -- grid布局
        self.ip_label = tk.Label(root, text="IP地址:")
        self.ip_label.grid(row=0, column=0)
        self.ip_entry = tk.Entry(root)
        self.ip_entry.grid(row=0, column=1)
        self.ip_entry.insert(0, "192.168.100.10")  # 默认 IP 地址

        self.port_label = tk.Label(root, text="端口:")
        self.port_label.grid(row=0, column=2)
        self.port_entry = tk.Entry(root)
        self.port_entry.grid(row=0, column=3)
        self.port_entry.insert(0, "161")  # 默认端口

        self.community_label = tk.Label(root, text="Community字符串:")
        self.community_label.grid(row=0, column=4)
        self.community_entry = tk.Entry(root)
        self.community_entry.grid(row=0, column=5)
        self.community_entry.insert(0, "Private")  # 默认 Community 字符串

        self.version_label = tk.Label(root, text="SNMP版本:")
        self.version_label.grid(row=0, column=6)
        self.version_var = tk.StringVar(value='v1')  # 默认 SNMP 版本
        self.version_menu = ttk.Combobox(root, textvariable=self.version_var, values=["v1", "v2c"])
        self.version_menu.grid(row=0, column=7)

        # 树形框架
        self.tree_frame = tk.Frame(root)
        self.tree_frame.grid(row=1, column=0, columnspan=8, sticky='wse')

        # 树形控件设置
        self.tree = ttk.Treeview(self.tree_frame, show='tree')  # show 参数须指定为 tree，否则在树顶上出现 'heading' 空行
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar = tk.Scrollbar(self.tree_frame, command=self.tree.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.config(yscrollcommand=self.scrollbar.set)

        # 输出框字体设置
        output_font = font.Font(family='JetBrains Mono', size=10)

        # 输出框架设置
        self.output_frame = tk.Frame(root)
        self.output_frame.grid(row=2, column=0, columnspan=8, sticky='wse')

        # 输出信息框设置
        self.output_box = tk.Text(self.output_frame, wrap='word', bg='lightyellow', 
                                  bd=2, relief='groove', height=10, width=50,
                                  font=output_font)
        self.output_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 输出框滚动条设置
        self.scrollbar = tk.Scrollbar(self.output_frame, command=self.output_box.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 配置文本框使用滚动条
        self.output_box.config(yscrollcommand=self.scrollbar.set)

        # 树形控件绑定事件
        self.tree.bind("<ButtonRelease>", self.print_click)  # 单击松开事件
        self.tree.bind("<Button-3>", self.show_context_menu)  # 右键点击事件

        # 定义 MIB 树结构
        self.tree_root = self.tree.insert("", "end", "TreeRoot", text="Root")

        # 从华为信息中心选取的根 OID
        self.root_oids = {
            "r_System":    "1.3.6.1.2.1.1",  # 系统信息
            "r_ifEntity":  "1.3.6.1.2.1.2.2.1",  # 接口实体
            "r_icmp":      "1.3.6.1.2.1.5",  # ICMP 信息
            "r_snmpEngine": "1.3.6.1.6.3.10.2.1",  # SNMP 引擎
            "r_pingMaxCR": "1.3.6.1.2.1.80.1.1"  # ping 最大并发请求数
        }

        # 添加根节点
        self.rsystem_node = self.tree.insert(self.tree_root, "end", "r_System", text="系统")
        self.rifEntity_node = self.tree.insert(self.tree_root, "end", "r_ifEntity", text="接口实体")
        self.ricmp_node = self.tree.insert(self.tree_root, "end", "r_icmp", text="icmp")
        self.rsnmp_node = self.tree.insert(self.tree_root, "end", "r_snmpEngine", text="snmp引擎")
        self.rping_node = self.tree.insert(self.tree_root, "end", "r_pingMaxCR", text="ping当前最大请求数")
        
        # 添加系统子节点
        self.system_oids = {
            "系统描述": "1.3.6.1.2.1.1.1",  # 系统描述
            "系统运行时间": "1.3.6.1.2.1.1.3",  # 系统运行时间
            "系统联系人": "1.3.6.1.2.1.1.4",  # 系统联系人
            "系统名称": "1.3.6.1.2.1.1.5",  # 系统名称
            "系统位置": "1.3.6.1.2.1.1.6",  # 系统位置
            "系统服务": "1.3.6.1.2.1.1.7",  # 系统服务
            "系统接口数量": "1.3.6.1.2.1.2.1"  # 系统接口数量
        }
        for oid_name in self.system_oids.keys():
            self.tree.insert(self.rsystem_node, "end", oid_name, text=oid_name)

        # 添加接口实体子节点
        self.ifEntity_oids = {
            "接口描述": "1.3.6.1.2.1.2.2.1.2",  # 接口描述
            "接口最大传输单元": "1.3.6.1.2.1.2.2.1.4",  # 接口最大传输单元
            "接口速度": "1.3.6.1.2.1.2.2.1.5",  # 接口速度
            "接口管理状态": "1.3.6.1.2.1.2.2.1.7",  # 接口管理状态
            "接口操作状态": "1.3.6.1.2.1.2.2.1.8",  # 接口操作状态
            "接口最后变更时间": "1.3.6.1.2.1.2.2.1.9",  # 接口最后变更时间
            "接口输入字节数": "1.3.6.1.2.1.2.2.1.10",  # 接口输入字节数
            "接口输出字节数": "1.3.6.1.2.1.2.2.1.16",  # 接口输出字节数
        }
        for oid_name in self.ifEntity_oids.keys():
            self.tree.insert(self.rifEntity_node, "end", oid_name, text=oid_name)

        # 添加 ICMP 子节点
        self.icmp_oids = {
            "ICMP输入消息数": '1.3.6.1.2.1.5.1',  # ICMP 输入消息数
            "ICMP输入回显请求数": '1.3.6.1.2.1.5.8',  # ICMP 输入回显请求数
            "ICMP输出消息数": '1.3.6.1.2.1.5.14',  # ICMP 输出消息数
            "ICMP输出回显应答数": '1.3.6.1.2.1.5.22',  # ICMP 输出回显应答数
        }
        for oid_name in self.icmp_oids.keys():
            self.tree.insert(self.ricmp_node, "end", oid_name, text=oid_name)

        # 添加 SNMP 子节点
        self.snmp_oids = {
            "SNMP引擎ID": '1.3.6.1.6.3.10.2.1.1',  # SNMP 引擎 ID
            "SNMP引擎启动次数": '1.3.6.1.6.3.10.2.1.2',  # SNMP 引擎启动次数
            "SNMP引擎时间": '1.3.6.1.6.3.10.2.1.3',  # SNMP 引擎时间
            "SNMP引擎最大消息大小": '1.3.6.1.6.3.10.2.1.4'  # SNMP 引擎最大消息大小
        }
        # 1.3.6.1.2.1.2.2.1.14
        
        for oid_name in self.snmp_oids.keys():
            self.tree.insert(self.rsnmp_node, "end", oid_name, text=oid_name)

    def print_click(self, event):
        """打印选中的树节点"""
        selected_item = self.tree.selection()
        print(selected_item)

    def show_context_menu(self, event):
        """显示右键菜单"""
        selected_item = self.tree.selection()
        if selected_item:
            context_menu = tk.Menu(self.root, tearoff=0)
            context_menu.add_command(label="Get", command=lambda: self.get_oid(selected_item[0]))  # 获取 OID
            context_menu.add_command(label="GetNext", command=lambda: self.get_next_oid(selected_item[0]))  # 获取下一个 OID
            context_menu.add_command(label="Walk", command=lambda: self.walk_oid(selected_item[0]))  # 遍历 OID
            context_menu.add_command(label="Set", command=lambda: self.set_oid(selected_item[0]))  # 设置 OID
            context_menu.post(event.x_root, event.y_root)

    def get_oid(self, oid_name):
        """获取指定 OID 的值"""
        if oid_name not in self.system_oids:
            messagebox.showwarning("Invalid Selection", "请选择一个有效的 OID 进行获取")
            return
        ip = self.ip_entry.get()
        if check_ip(ip) == False:
            messagebox.showwarning("Invalid Input", "请输入有效的 IP 地址")
            return
        port = int(self.port_entry.get())
        if check_port(port) == False:
            messagebox.showwarning("Invalid Input", "请输入有效的端口")
            return
        community = self.community_entry.get()
        version = self.version_var.get()
        print("func, get_oid:"+ip, port, community, version)

        if version == 'v1':
            snmp_version = 0
        elif version == 'v2c':
            snmp_version = 1
        else:
            snmp_version = 0

        oid = self.system_oids[oid_name]+'.'
        oid = oid+str(snmp_version)
        print(oid)
        iterator = getCmd(SnmpEngine(),
                          CommunityData(community, mpModel=snmp_version),
                          UdpTransportTarget((ip, port)),
                          ContextData(),
                          ObjectType(ObjectIdentity(oid))
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication:
            self.output_box.insert(tk.END, f"Error: {errorIndication}\n")
        elif errorStatus:
            self.output_box.insert(tk.END, f"Error: {errorStatus.prettyPrint()}\n")
        else:
            for varBind in varBinds:
                    formatted = format_snmp_output(varBind)
                    self.output_box.insert(tk.END, f"{formatted}\n")
                    self.output_box.see(tk.END)  # 自动滚动到文本框的末尾

    def get_next_oid(self, oid_name):
        """获取下一个 OID 的值"""
        if oid_name not in self.system_oids:
            messagebox.showwarning("Invalid Selection", "请选择一个有效的 OID 进行获取下一个")
            return
        ip = self.ip_entry.get()
        if check_ip(ip) == False:
            messagebox.showwarning("Invalid Input", "请输入有效的 IP 地址")
            return
        port = int(self.port_entry.get())
        if check_port(port) == False:
            messagebox.showwarning("Invalid Input", "请输入有效的端口")
            return
        community = self.community_entry.get()
        version = self.version_var.get()
        print("func, get_next_oid:"+ip, port, community, version)

        if version == 'v1':
            snmp_version = 0
        elif version == 'v2c':
            snmp_version = 1
        else:
            snmp_version = 0

        oid = self.system_oids[oid_name]+'.'
        oid = oid+str(snmp_version)
        print(oid)
        iterator = nextCmd(SnmpEngine(),
                          CommunityData(community, mpModel=snmp_version),
                          UdpTransportTarget((ip, port)),
                          ContextData(),
                          ObjectType(ObjectIdentity(oid))
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication:
            self.output_box.insert(tk.END, f"Error: {errorIndication}\n")
        elif errorStatus:
            self.output_box.insert(tk.END, f"Error: {errorStatus.prettyPrint()}\n")
        else:
            for varBind in varBinds:
                    formatted = format_snmp_output(varBind)
                    self.output_box.insert(tk.END, f"{formatted}\n")
                    self.output_box.see(tk.END)  # 自动滚动到文本框的末尾

    def walk_oid(self, oid_name):
        """遍历指定 OID 的所有子节点"""
        print("oidName"+oid_name)
        if oid_name not in self.root_oids and oid_name not in self.ifEntity_oids and oid_name not in self.icmp_oids and oid_name not in self.snmp_oids:
            messagebox.showwarning("Invalid Selection", "请选择一个有效的 OID 进行遍历")
            return

        ip = self.ip_entry.get()
        if check_ip(ip) == False:
            messagebox.showwarning("Invalid Input", "请输入有效的 IP 地址")
            return
        port = int(self.port_entry.get())
        if check_port(port) == False:
            messagebox.showwarning("Invalid Input", "请输入有效的端口")
            return
        
        community = self.community_entry.get()
        version = self.version_var.get()

        if version == 'v1':
            snmp_version = 0
        elif version == 'v2c':
            snmp_version = 1
        else:
            snmp_version = 0

        if oid_name.startswith('r'):
            oid = self.root_oids[oid_name]
        elif oid_name.startswith('接口'):
            oid = self.ifEntity_oids[oid_name]
        elif oid_name.startswith('ICMP'):
            oid = self.icmp_oids[oid_name]
        elif oid_name.startswith('SNMP'):
            oid = self.snmp_oids[oid_name]
        else:
            pass

        print("func, walk_oid:"+ip, port, community, version, oid)
        
        # 使用 nextCmd 进行遍历
        iterator = nextCmd(SnmpEngine(),
                        CommunityData(community, mpModel=snmp_version),
                        UdpTransportTarget((ip, port)),
                        ContextData(),
                        ObjectType(ObjectIdentity(oid)),
                        lexicographicMode=False)

        while True:
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

            if errorIndication:
                self.output_box.insert(tk.END, f"Error: {errorIndication}\n")
                break
            elif errorStatus:
                self.output_box.insert(tk.END, f"Error: {errorStatus.prettyPrint()}\n")
                break
            elif not varBinds:
                break  # 没有更多数据可获取
            else:
                for varBind in varBinds:
                    formatted = format_snmp_output(varBind)
                    self.output_box.insert(tk.END, f"{formatted}\n")
                    self.output_box.see(tk.END)  # 自动滚动到文本框的末尾

    def set_oid(self, oid_name):
        """设置指定 OID 的值"""
        if oid_name not in self.system_oids:
            messagebox.showwarning("Invalid Selection", "请选择一个有效的 OID 进行设置")
            return
        value = simpledialog.askstring("Set OID", "输入要设置的值:")
        print("set_oid func:"+value)
        if value is not None:
            ip = self.ip_entry.get()
            if check_ip(ip) == False:
                messagebox.showwarning("Invalid Input", "请输入有效的 IP 地址")
                return
            port = int(self.port_entry.get())
            if check_port(port) == False:
                messagebox.showwarning("Invalid Input", "请输入有效的端口")
                return
            community = self.community_entry.get()
            version = self.version_var.get()

            if version == 'v1':
                snmp_version = 0
            elif version == 'v2c':
                snmp_version = 1
            else:
                snmp_version = 0

            # 合成oid
            oid = self.system_oids[oid_name]+'.'
            oid = oid+str(snmp_version)

            print("func, set_oid:"+ip, port, community, version, oid, value)
            
            iterator = setCmd(SnmpEngine(),
                              CommunityData(community, mpModel=snmp_version),
                              UdpTransportTarget((ip, port)),
                              ContextData(),
                              ObjectType(ObjectIdentity(oid), value)
                              )

            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

            if errorIndication:
                self.output_box.insert(tk.END, f"Error: {errorIndication}\n")
            elif errorStatus:
                self.output_box.insert(tk.END, f"Error: {errorStatus.prettyPrint()}\n")
            else:
                self.output_box.insert(tk.END, f"成功将 {oid} 设置为 {value}。\n")

def check_ip(ip):
    """检查 IP 地址是否有效"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def check_port(port):
    """检查端口号是否有效"""
    return isinstance(port, int) and 0 <= port <= 65535     

def format_snmp_output(snmp_output):
    """格式化 SNMP 输出"""
    formatted_output = []
    
    # 如果 snmp_output 是单个 ObjectType 对象，将其转换为列表
    if isinstance(snmp_output, ObjectType):
        snmp_output = [snmp_output]
    
    for obj in snmp_output:
        # 将 ObjectType 对象转换为字符串
        line = str(obj)
        
        # 找到第二个冒号的位置
        second_colon_index = line.find(':', line.find(':') + 1)
        
        # 如果找到第二个冒号，则删除前面的部分
        if second_colon_index != -1:
            formatted_line = line[second_colon_index + 1:].strip()
            formatted_output.append(formatted_line)
        else:
            # 如果没有第二个冒号，保留原行
            formatted_output.append(line.strip())
    
    return '\n'.join(formatted_output)

if __name__ == "__main__":
    # 美化主题，链接：https://wiki.tcl-lang.org/page/List+of+ttk+Themes
    root = ThemedTk(theme='clearlooks', toplevel=True, themebg=True)
    root.minsize(width=850, height=360)
    app = MIBTreeBrowser(root)
    root.mainloop()