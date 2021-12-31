import socket
import subprocess
import tkinter
from tkinter import *
from socket import *
from tkinter import messagebox,ttk
import threadpool
from tkinter import scrolledtext
import re



ports = []
stop = False
task = 0
flag = True
cmd = ''
closeflag = 0

def check_ip(ipAddr):
    compile_ip = re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if compile_ip.match(ipAddr):
        return True
    else:
        return False

def whichOs(type):
    if type == 21:
        strType = "21端口主要用于FTP（File Transfer Protocol，文件传输协议）服务"
    elif type == 23:
        strType = "23端口主要用于Telnet（远程登录）服务"
    elif type == 25:
        strType = "25端口为SMTP（Simple Mail Transfer Protocol，简单邮件传输协议）"
    elif type == 53:
        strType = "53端口为DNS（Domain Name Server，域名服务器）服务器所开放，主要用于域名解析"
    elif type == 67:
        strType = "67端口是Bootp服务的Bootstrap Protocol Server（引导程序协议服务端）开放的端口"
    elif type == 68:
        strType = "68端口是Bootstrap Protocol Client（引导程序协议客户端）开放的端口"
    elif type == 69:
        strType = "69端口是为TFTP（Trival File Tranfer Protocol，次要文件传输协议）服务开放"
    elif type == 79:
        strType = "79端口是为Finger服务开放的"
    elif type == 80:
        strType = "80端口是为HTTP（HyperText Transport Protocol，超文本传输协议）开放的"
    elif type == 109:
        strType = "109端口是为POP2（Post Office Protocol Version 2，邮局协议2）服务开放的"
    elif type == 110:
        strType = "110端口是为POP3（邮件协议3）服务开放的"
    elif type == 111:
        strType = "111端口是RPC（Remote Procedure Call，远程过程调用）服务所开放的端口"
    elif type == 113:
        strType = "113端口主要用于Windows的“Authentication Service”（验证服务）"
    elif type == 119:
        strType = "119端口是为“Network News Transfer Protocol”（网络新闻组传输协议，简称NNTP）开放的"
    elif type == 161:
        strType = "SNMP(简单网络管理协议)是基于UDP端口161"
    elif type == 443:
        strType = "443端口即网页浏览端口，主要是用于HTTPS服务"
    elif type == 1433:
        strType = "SQLServer默认端口号为1433"
    elif type == 1521:
        strType = "oracle数据库的默认端口1521"
    elif type == 3306:
        strType = "3306端口为MySQL的默认端口"
    elif type == 8000:
        strType = "8000端口：腾讯QQ服务器端开放此端口"
    elif type == 8080:
        strType = "Apache Tomcat Web Server默认的服务端口为8080"
    else:
        strType = "未知服务类型"
    return strType

class PortScanner(object):
    def __init__(self):
        #初始化一个主窗口
        self.root = Tk()
        self.root.title("Port Scan")
        self.root.configure(bg='#f1c4cd') #f9e9cd #f1c4cd #e2c027
        self.root.geometry("886x770")
        self.root.minsize(886, 770)

        self.ip = StringVar()
        self.start_port = StringVar()
        self.end_port = StringVar()
        self.threaders = StringVar()
        self.checkbtn = StringVar()
        self.choice = StringVar()
        self.bar = StringVar()



        self.gui()


    def gui(self):

        # 界面分为上中下的3个Frame
        # f1放置第一行 “目标”标签和文本框 “配置”标签和选择项 “扫描”按钮  “取消”按钮
        self.f1 = Frame(self.root)
        self.f1.configure(bg='#f1c4cd')
        self.f1.pack(pady=10, ipadx=100, fill='x',padx=50)  # 如果f1组件没有pack（）的话，那么子组件Label，Entry无法显示
        Label(self.f1, text="目标",font=('楷体', 14)).pack(side=LEFT, padx=10)
        Entry(self.f1,textvariable=self.ip,font=('楷体', 14)).pack(side=LEFT)
        Label(self.f1, text="配置",font=('楷体', 14)).pack(side=LEFT, padx=10)
        om = ttk.OptionMenu(self.f1, self.choice,'','单IP', 'IP段',command=self.change_option)
        om['width'] = '10'
        om.pack(side=LEFT)
        self.startButton = Button(self.f1, text='开始扫描',font=('楷体', 14), command=self.start_scan_button)
        self.startButton.pack(side=LEFT, padx=10)
        self.startButton.config(state=tkinter.NORMAL)
        self.stopButton = Button(self.f1, text='停止扫描',font=('楷体', 14),command=self.end_scan_button)
        self.stopButton.pack(side=LEFT, padx=10)
        self.stopButton.config(state=tkinter.DISABLED)
        Button(self.f1, text='清空',font=('楷体', 14),command=self.clear_text).pack(side=LEFT, padx=10)
        # Button(self.f1, text='退出', command=self.root.quit).pack(side=LEFT, padx=10)

        # f2放置第二行 “开始端口”标签 和 文本框  “最终端口”标签 和 文本框  “线程”标签 和 文本框
        self.f2 = Frame(self.root)
        self.f2.configure(bg='#f1c4cd')
        self.f2.pack(pady=5,padx=50,fill='x')
        Label(self.f2, text='起始端口',font=('楷体', 14)).pack(side=LEFT, padx=10)
        Entry(self.f2,textvariable=self.start_port,width=8,font=('楷体', 14)).pack(side=LEFT)

        Label(self.f2, text='终止端口',font=('楷体', 14)).pack(side=LEFT, padx=10)
        Entry(self.f2,textvariable=self.end_port,width=8,font=('楷体', 14)).pack(side=LEFT)

        Label(self.f2, text='线程数',width=5,font=('楷体', 14)).pack(side=LEFT, padx=10)
        self.threaders.set(3)
        Entry(self.f2,textvariable=self.threaders,width=6,font=('楷体', 14)).pack(side=LEFT)
        self.checkbtn.set('yes')
        self.checkbutton = Checkbutton(self.f2,text='显示可达连接',variable=self.checkbtn,onvalue='yes',offvalue='no',font=('楷体', 14))
        self.checkbutton.pack(side=LEFT,padx=30)

        # f3 放置第三个 “输出”文本
        self.f3 = Frame(self.root)
        self.f3.configure(bg='#f1c4cd')
        Label(self.f3, text='扫描结果', bg='white',font=('楷体', 14)).pack()
        self.f3.pack(pady=5)
        self.text = scrolledtext.ScrolledText(self.f3, font=('楷体', 15))
        self.text.pack(side=LEFT)
        self.text['width'] = 65

        self.f4 = Frame(self.root)
        self.bar_entry = Entry(self.f4, text="Label",state='disabled')
        self.bar_entry.pack(side=LEFT)
        self.bar_entry['width'] = 150

        self.f4.pack(pady=5)
        self.root.mainloop()


    #配置类型的判断
    def change_option(self,val):
        if val == 'IP段':
            messagebox.showinfo(message=('提示：ip段类型的目标写法规范,如：192.168.4.1-192.168.4.10\n'))

    #获取ip和端口的列表
    #[(None, {'ip': '127.0.0.1', 'port': 1}), (None, {'ip': '127.0.0.1', 'port': 2}), \
    # (None, {'ip': '127.0.0.2', 'port': 1}), (None, {'ip': '127.0.0.2', 'port': 2}), \
    # (None, {'ip': '127.0.0.3', 'port': 1}), (None, {'ip': '127.0.0.3', 'port': 2})]
    def get_ip_port(self):
        # ports = []
        global ports
        #先判断5个框是否为空
        if self.start_port.get() == '' or self.end_port.get() == '': # 先判断端口值是否为空,如果错了，直接返回false，如果没有错就判断下一个输入框
            messagebox.showerror(title='错误', message='端口参数不能为空！')
            return False
        elif self.ip.get() == '': # 判断ip是否为空
            messagebox.showerror(title='错误', message='IP地址参数不能为空！')
            return False
        elif self.threaders.get() == '': # 线程数是否为空
            messagebox.showerror(title='错误', message='线程数不能为空！')
            return False
        elif self.choice.get() == '': #扫描类型为空
            messagebox.showerror(title='错误', message='扫描类型要做选择！')
            return False
        int_start_port = int(self.start_port.get()) #将开始端口转为int
        int_end_port = int(self.end_port.get())
        threaders = int(self.threaders.get())

        if int_start_port < 0 or int_end_port > 65535  :
            messagebox.showerror(title='错误', message='端口范围为0-65535!')
            return False
        elif int_start_port > int_end_port:
            messagebox.showerror(title='错误', message='起始端口需要小于终止端口!')
            return False

        elif threaders<0 or threaders >11:
            messagebox.showerror(title='错误', message='线程数的范围：1-10！')
            return False
        #后面判断5个框的参数是否合法
        elif True:
            ip = self.ip.get()
            if self.choice.get() == '单IP':
                if check_ip(ip) == False:
                    messagebox.showerror(title='错误', message='IP不符合规范,如：192.168.4.1')
                    return False
                for p in range(int(self.start_port.get()), int(self.end_port.get()) + 1): #遍历所有的端口
                    dict_var = {'ip':ip,'port':p}#因为调用makeRequests函数的相关参数需要有固定格式，所以先将ip和port用字典存储
                    ports.append((None,dict_var)) #将上面的字典dict_var 与 None合成一个元组，然后放在ports列表当中
            else:
                try:
                    (BeginIP, EndIP) = ip.split("-") #如果Begin
                except:
                    messagebox.showerror(title='错误', message='IP段的写法不规范,如：192.168.4.1-192.168.4.10')
                    return False
                if check_ip(BeginIP) == False or check_ip(EndIP) == False:
                    messagebox.showerror(title='错误', message='IP不符合规范,如：192.168.4.1')
                    return False
                IPRange = BeginIP[0:BeginIP.rfind('.')]
                begin = BeginIP[BeginIP.rfind('.') + 1:]  # 取 IP 的最后一个网段数字
                end = EndIP[EndIP.rfind('.') + 1:]
                for i in range(int(begin), int(end) + 1):  # int(begin)-int(end)
                    strIP = "%s.%s" % (IPRange, i)
                    for p in range(int(self.start_port.get()), int(self.end_port.get()) + 1):
                        dict_var = {'ip': strIP, 'port': p}
                        ports.append((None, dict_var))
        return True


    def ping(self,ip):
        global cmd
        global flag

        if cmd != 'ping ' + ip + ' -c 5':  # 通过cmd控制IP一样的时候只执行一次 cmd 存上一次执行的ping命令
            cmd = 'ping ' + ip + ' -c 5'
            print(cmd)

            ret = subprocess.Popen(cmd, shell=True,
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)  #实现获取命令行实时输出
            for i in iter(ret.stdout.readline, b""):
                # iter()生成迭代数  ret.stdout.readline 输出的是什么，process.stdout是字节流对象用readlines()读取文件内容；
                datas = i.decode(encoding='gbk').strip()  # strip()是除掉首尾的空格
                print(datas)
                try:
                   ttl = re.compile('(ttl)=\d*').search(datas).group()[4:]
                   print(ttl)
                   flag = False
                except:
                    pass
            
            if flag == False:
                print("ttl: {}".format(ttl))
                if ttl == '128':
                    self.text.insert(END, "ip地址：%s   操作系统类型：Windows NT/2000/XP\n" % ip)
                elif ttl == '64':
                    self.text.insert(END, "ip地址：%s   操作系统类型：Linux\n" % ip)
                elif ttl == '32':
                    self.text.insert(END, "ip地址：%s   操作系统类型：Windows98\n" % ip)
                elif ttl == '255':
                    self.text.insert(END, "ip地址：%s   操作系统类型：Linux/Unix\n" % ip)
                else:
                    self.text.insert(END, "ip地址：%s   操作系统类型：未知\n" % ip)
            else:
                self.text.insert(END, "ip地址：%s    请求超时！\n" % ip)
            self.text.see(END)

    def con(self,ip,port):
        global closeflag
        s = socket()
        s.settimeout(4)
        try:
            statu = s.connect_ex((ip, port))
            if self.checkbtn.get() == 'yes':  # 显示可达连接的单选框，一开始设置是yes，显示勾选，只显示可达
                if statu == 0:
                    self.text.tag_config("tag1", foreground="green")
                    self.text.insert('end', "IP地址: %s 端口: %d is open %s\n" % (ip, port, whichOs(port)), "tag1")
                else:
                    closeflag = closeflag + 1
                    # print(closeflag)
            else:  # 可达与不可达都出现
                #print("{}1".format(port))
                if statu == 0:
                    # print("{}2".format(port))
                    self.text.tag_config("tag1", foreground="green")
                    self.text.insert('end', "IP地址: %s 端口: %d is open %s\n" % (ip, port, whichOs(port)), "tag1")
                else:
                    closeflag = closeflag + 1
                    self.text.tag_config("tag2", foreground="red")
                    self.text.insert('end', "IP地址: %s 端口: %d is timeout\n" % (ip, port), "tag2")
                self.text.see(END)
            self.text.see(END)
            #sys.stdout.write("task{:} \n".format(task))
        except:
            pass
        finally:
            s.close()
        global flag
        flag = True
        #print("closeflag:%d"%closeflag)


    # 每个线程要执行的任务函数
    def scan_port(self, ip, port):  # 传经来的端口列表

        global task  # 任务标志
        global stop  # 停止标志，如果stop等于false才可以进行下面的代码执行
        #print(stop)
        if stop == False:
            # 通过ttl值来初步判断操作系统的类型
             self.ping(ip)

            # connect连接 判断端口开放
             self.con(ip,port)

        task = task + 1 #如果stop =True,那么上面不执行，直接跳下面，但是线程池的任务还是会执行完，所以task最终还是会等于总数

        if task == len(ports) :
            if closeflag == len(ports):
                self.text.tag_config("tag3", foreground="#2e317c") #525288
                self.text.insert('end', "           没有开放的端口!\n","tag3")
                self.text.see(END)
            if stop == True :
                self.text.insert('end', "=======扫描停止，请点击'开始扫描'重新扫描=======\n")
            else:
                self.startButton.config(state=tkinter.NORMAL)
                self.stopButton.config(state=tkinter.DISABLED)
                self.text.insert('end', "==============扫描完成==============\n")
            self.text.see(END)



    #点击"开始扫描"触发的事件
    def start_scan_button(self):
        global stop, task, cmd, flag, closeflag
        stop = False
        task = 0
        cmd = ''
        # print(flag)
        closeflag = 0

        ports.clear() #ports是全局变量，如果不清空，第二次重新扫描还是会出现第一次规定的端口列表开始扫
        if self.get_ip_port():#这个函数先检验参数，然后无误才可以正确获取ports列表

            self.startButton.config(state=tkinter.DISABLED) #点击开始扫描，按钮变成不可点击
            self.stopButton.config(state=tkinter.NORMAL) #此时停止按钮变成可点击
            #print(ports)
            self.text.insert(END, "==============扫描开始==============\n")
            self.text.see(END)
            threaders = int(self.threaders.get()) #获取线程数
            pool = threadpool.ThreadPool(threaders)  # 定义了一个线程池，表示最多可以创建threaders这么多线程
            reqs = threadpool.makeRequests(self.scan_port, ports)  # 调用makeRequests创建了要开启多线程的函数，以及函数相关参数
            [ pool.putRequest(req) for req in reqs] # 循坏是将所有要运行多线程的请求扔进线程池

    #点击"停止扫描"触发的事件
    def end_scan_button(self):
        global stop
        stop = True
        self.startButton.config(state=tkinter.NORMAL)
        self.stopButton.config(state=tkinter.DISABLED)

    #清空
    def clear_text(self):
        self.text.delete(1.0, tkinter.END)



if __name__ == '__main__':

    portscanner = PortScanner()








