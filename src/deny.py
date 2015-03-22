#!/usr/bin/env python

# description: analysist apache logs, block attckers' ip
# author: Zhengfeng Rao<gisrzf@163.com>
# date: 2015/3/17

import logging
import sys
import time
import os

import daemon
import conf

def LoadDenyList():
    try:
        if not os.path.exists(conf.data_directory):
            os.makedirs(conf.data_directory)

        fd = open(conf.data_directory + os.sep + conf.deny_file, "r")
        ips = fd.read().splitlines()
        fd.close()
        return ips
    except:
        return []

def SaveDenyList(ips):
    fd = open(conf.data_directory + os.sep + conf.deny_file, 'w')
    for ip in ips:
        fd.writelines(ip + "\n")
    fd.close()

def AddIptablesRule(ips):
    for ip in ips:
        cmd = conf.iptables_command_prefix + ip + conf.iptables_command_suffix
        logging.info(cmd)
        os.system(cmd)

def RunCommands(ips):
    new_ips = []
    for command in conf.analysis_commands:
        deny_list = os.popen(command, 'r').read().splitlines()
        for ip in deny_list:
            if ip not in ips:
                logging.info("found:" + ip)
                ips.append(ip)
                new_ips.append(ip)
    return ips, new_ips

def DoJob():
    deny_list = LoadDenyList()
    result = RunCommands(deny_list)
    SaveDenyList(result[0])
    AddIptablesRule(result[1])

def CheckRoot():
    if os.geteuid() != 0:
        logging.warn("*** This program requires root privilege. ***")
        args = [sys.executable] + sys.argv
        os.execlp('su', 'su', '-c', ' '.join(args))
        # os.execlp('sudo', 'sudo', *args)

class App(daemon.Daemon):
    def usage(self):
        print __file__ + ' test|start|stop'
        print 'test: no daemon, run once, output log to stdout'
        print 'start: start job'
        print 'stop: exit job'

    def run(self):
        while True:
            DoJob()
            time.sleep(conf.run_interval * 60)

if __name__ == '__main__':
    CheckRoot()
    app = App(conf.pid_file)

    if len(sys.argv) < 2:
        app.usage()
    elif sys.argv[1] == 'test':
        logging.basicConfig(level= conf.log_level,
            format= conf.log_format,
            datefmt= conf.log_date_format)
        DoJob()
    else:
        logging.basicConfig(level= conf.log_level,
            format= conf.log_format,
            datefmt= conf.log_date_format,
            filename= conf.log_file,
            filemode='w')
        if sys.argv[1] == 'start':
            app.start()
        elif sys.argv[1] == 'stop':
            app.stop()
        else:
            print("Invalid commond.")