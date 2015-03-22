import  logging

#app configure
run_interval = 1 #minutes
pid_file = '/var/tmp/httpd_log_2_iptables.deny.pid'

#data
data_directory = '/home/rao/ITNiuren/data/security/'
deny_file = 'deny_ips.txt'

#log
log_logger_name = "httpd_log_2_iptables"
log_level = logging.DEBUG
# https://docs.python.org/2/library/logging.html#logrecord-attributes
log_format = '[%(asctime)s][%(levelname)s][%(thread)d][%(filename)s:%(lineno)d]%(message)s'
log_date_format = '%Y-%m-%d %H:%M:%S'
log_file = '/home/rao/ITNiuren/data/log/deny.log'

#apache log analysis commands
analysis_commands = [
	#forbide attack with string mtvnservices
	"cat /var/log/httpd/access_log |grep mtvnservices |awk '{print $1}'|sort|uniq |sort -nr",

	#forbide 403 access
	#118.194.41.34 - - [15/Mar/2015:08:54:16 +0000] "CONNECT mail.qq.com:443 HTTP/1.1" 403 1374 "-" "Jakarta Commons-HttpClient/3.1"
        "cat /var/log/httpd/access_log|awk '{if($9=='403'){print $1}}'|sort|uniq|sort -nr",

	#forbide brute force attack
	#117.36.86.59 - - [16/Mar/2015:22:58:21 +0000] "GET http://mobile.baidu.com/ap........
	"cat /var/log/httpd/access_log|awk '{if($9 == '404'){split($7, array, \"/\"); if(!match(array[2], \"article|tag|source|static|channel|favicon.ico|ui-designer|robots.txt\")){print $1}}}'|sort|uniq -c|sort -nr|awk '{if($1 >= 10) {print $2}}'"
	]
iptables_command_prefix = "iptables -I  INPUT -s "
iptables_command_suffix = " -j DROP"
