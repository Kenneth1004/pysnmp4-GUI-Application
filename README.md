# pysnmp4-GUI Application Chinese README
Orz懒得敲了，英文凑合看着先吧
# pysnmp4-GUI-Application English README
This App is a GUI for SNMP operations, built using tkinter and pysnmp 4.4.12. Use ttkthemes to beautify.
***
![图片1](https://github.com/user-attachments/assets/46567f4e-f9d0-40a2-b978-1343fa45d10e)
***
It allows users to browse a simple MIB tree, perform SNMP operations(GET, GETNEXT, WALK, SET) by just right-clicking, and view the results in an user-friendly interface.

# Installation
**Python3.7 or lower(as pysnmp 4.4.12 does not support higher versions).**

Python installer may install tkinter automactically if you choose 'Tk' option.
## Open a terminal and run the following commands:
```
> pip install pysnmp==4.4.12,ttkthemes
```
## Run
```
> python.exe snmpApp.py
```
# Usage
## Enter Target Device Information
Inputing IP address, port, community string and select the SNMP version(v1 or v2c)
## Browse MIB Tree(pre-definded)
Expand the MIB tree nodes to view available OIDs. 
## Perform SNMP Operations
Right-Click on any OID to perform GET,GETNEXT,WALK or SET operations.

*Attention, some OID may not support GET or GETNEXT operation directily , Application may warn you by a messagebox*
## View Output
The output box will display the results of the SNMP operations in a formatted manner.

# Refer to these links
https://jcutrer.com/howto/networking/mikrotik/mikrotik-snmp-reboot-script

https://gitee.com/suzhanhong/net-env-monitor-alert-open/blob/develop/olt_msg/msg_form_snmpoid.py

https://zhuanlan.zhihu.com/p/659516804

https://www.jianshu.com/p/09349a17e7fe
