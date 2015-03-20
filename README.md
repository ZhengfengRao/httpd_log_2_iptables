analysis apache log, add attacker's source ip to iptables to block.
<br>扫描apache日志，将恶意访问（攻击）者的ip自动加到iptables中过滤掉。



###Notice 注意事项：

1. because it will add rules to iptables, so root privilege is needed.
<br>运行时需要root权限来添加iptables规则。

2. this tool will run in daemon mode.
<br>本工具以daemon进程的形式运行。



###Steps to use this tool 使用步骤：
* edit conf.py to set your data file path and log settings, update your block rules and other settings.
<br>编辑 conf.py文件，设置数据文件路径和日志，定制过滤规则。
<br>
<br><font color="green">#this tool will check apache log every *run_interval* minutes.</font>
<br><font color="green">#每隔*run_interval*分钟扫描apache日志.</font>
<br>run_interval = 1 #minutes
<br>  
<br><font color="green">#the blocked ip will be listed in file *data_directory/deny_file*.</font>
<br><font color="green">#被过滤的ip地址列表位于*data_directory/deny_file*文件中.</font>
<br>data_directory = './security/'
<br>deny_file = 'deny_ips.txt'
<br>
<br><font color="green">#apache log analysis commands:the source ip satisfy any one of these commands will be add to iptables filter rules</font>
<br><font color="green">#you can add your rules here</font>
<br><font color="green">#apache日志分析命令：满足这些条件的ip会被加入到iptables中过滤掉,你可以添加更多的命令</font>
<br>analysis_commands = [
<br><font color="green">*#forbide 403 access.*</font>
<br><font color="green">        #118.194.41.34 - - [15/Mar/2015:08:54:16 +0000] "CONNECT mail.qq.com:443 HTTP/1.1" 403 1374 "-" "Jakarta Commons-HttpClient/3.1"</font>
<br>        "cat /var/log/httpd/access_log|awk '{if($9=='403'){print $1}}'|sort|uniq|sort -nr",
<br>
<br><font color="green">*#forbide brute force attack*</font>
<br><font color="green">*#防止暴力攻击*</font>
<br><font color="green">#117.36.86.59 - - [16/Mar/2015:22:58:21 +0000] "GET http://mobile.baidu.com/ap......."</font>
<br>        "cat /var/log/httpd/access_log|awk '{if($9=='404'){print $1}}'|sort|uniq -c|sort -nr |awk '{if($1 >= 50){print $2}}'"
<br>        ]
<br>
* start 
<br>启动
<br>#./deny start
<br>WARNING:root:*** This program requires root privilege. ***
<br>Password: 
<br>
<br>it will require root privilege, input password of root user.
<br>要求root用户权限，输入root密码即可。
<br>
<br>this tool will run in background as daemon process.
<br>本程序将会以daemon进程的形式在后台运行。
<br>
<br>then everything is done, that's sample!
<br>活干完了，就这么简单！

* stop
<br>停止
<br>#./deny start

* test
<br>测试
<br>
<br>if you don't won't it run as a daemon process, you can use the following command:
<br>如果你不想使用daemon进程的形式运行，可以使用如下命令测试：
<br>#./deny test
