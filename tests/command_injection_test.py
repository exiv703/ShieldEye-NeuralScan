#!/usr/bin/env python3
"""
Test file with Command Injection vulnerabilities
This file contains intentional security vulnerabilities for testing purposes.
DO NOT use this code in production!
"""

import os
import subprocess
import sys

class SystemCommands:
    def ping_host(self, hostname):
        # VULNERABILITY: Command Injection - direct os.system
        os.system("ping -c 4 " + hostname)
    
    def check_disk_space(self, path):
        # VULNERABILITY: Command Injection - subprocess with shell=True
        cmd = f"df -h {path}"
        subprocess.call(cmd, shell=True)
    
    def list_directory(self, directory):
        # VULNERABILITY: Command Injection - os.popen
        result = os.popen("ls -la " + directory).read()
        return result
    
    def grep_logs(self, pattern, logfile):
        # VULNERABILITY: Command Injection - string concatenation with shell=True
        command = "grep '" + pattern + "' " + logfile
        output = subprocess.check_output(command, shell=True)
        return output.decode()
    
    def kill_process(self, pid):
        # VULNERABILITY: Command Injection - format string
        os.system("kill -9 {}".format(pid))
    
    def compress_file(self, filename, output):
        # VULNERABILITY: Command Injection - f-string with shell=True
        subprocess.run(f"tar -czf {output} {filename}", shell=True)

class FileOperations:
    def download_file(self, url, destination):
        # VULNERABILITY: Command Injection - wget/curl
        cmd = f"wget {url} -O {destination}"
        os.system(cmd)
    
    def extract_archive(self, archive_path):
        # VULNERABILITY: Command Injection - unzip
        subprocess.call("unzip " + archive_path, shell=True)
    
    def convert_image(self, input_file, output_file):
        # VULNERABILITY: Command Injection - imagemagick
        command = f"convert {input_file} {output_file}"
        os.popen(command)

class NetworkTools:
    def traceroute(self, host):
        # VULNERABILITY: Command Injection - traceroute
        result = subprocess.check_output(f"traceroute {host}", shell=True)
        return result
    
    def nslookup(self, domain):
        # VULNERABILITY: Command Injection - nslookup
        os.system("nslookup " + domain)
    
    def netcat_connect(self, host, port):
        # VULNERABILITY: Command Injection - netcat
        cmd = "nc {} {}".format(host, port)
        subprocess.Popen(cmd, shell=True)
    
    def scan_port(self, target, port):
        # VULNERABILITY: Command Injection - nmap
        os.popen(f"nmap -p {port} {target}")
