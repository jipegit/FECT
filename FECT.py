# -*- encoding: utf-8 -*-
#
#  FECT/FECT.py
#  
#  Author: Jean-Philippe Teissier ( @Jipe_ )
#    
#  This work is licensed under the GNU General Public License
#
#  Dependencies: pywin32
#

import subprocess
import re
import zipfile
import os
import sys
import argparse
import datetime
import pythoncom
import pywintypes
import win32api
from win32com.shell import shell
import platform
import hashlib
from functools import partial

__version__ = '0.3.2'

# Put your hex-encoded autorunsc.exe here
g_autorunsc_exe_hex_encoded = ''

g_debug_filehandle = None
g_md5s = []

def printandlog(logstr):
	''' print and log if the log handle is available '''
	
	global g_debug_filehandle

	print logstr
	if g_debug_filehandle is not None:
		g_debug_filehandle.write(logstr + '\r\n')

def chunkedmd5(filepath):
	""" Return the md5 hash of a big file """
	
	md5 = hashlib.md5()
	try:
		with open(filepath, 'rb') as f:
			for chunk in iter(partial(f.read, 1048576), ''):
				md5.update(chunk)
			return md5.hexdigest()
	except:
		printandlog('[!] Cannot hash ' + filepath)
		return ''

def Main():
	''' main '''
	
	global g_debug_filehandle
	global g_md5s

	parser = argparse.ArgumentParser(description='Use Microsoft autorunsc to identify binaries launched at windows startup and zip all the binaries to an archive')
	parser.add_argument('-a', '--autorunsc_options', help='Wrapped options passed to autorunsc. E.g.: pyAutoruns.py -a \"-b -s -c -f\" Double quotes are Mandatory. -c is Mandatory as well.')
	parser.add_argument('-k', '--key', help='The key to xor the zip archive with. Default if 0x42')

	args = parser.parse_args()

	print '\n[*] Fast Evidence Collector Toolkit v' + __version__ + ' by @Jipe_\n'

	if g_autorunsc_exe_hex_encoded == '':
		print '[!] Error autorunsc hex-encoded binary is missing'
		raise

	if shell.IsUserAnAdmin():
		print '[*] That\'s fine, I\'m running with Administrator privileges'

		autorunsc_options = '-a -c -m -f *'	#All entries with the respective hashes, except the one from Microsoft, with a CSV output 

		if args.autorunsc_options:
			autorunsc_options = args.autorunsc_options

		path_regex = re.compile('\"([a-z]:[\w\\\s-]+?\.\w{3})[\s\"]{1}', flags=re.IGNORECASE)			#match normal paths
		path_with_var_regex = re.compile('\"(%\w+%[\w\\\s-]+?\.\w{3})[\s\"]{1}', flags=re.IGNORECASE)	#match paths using an %environementvariables%

		systemroot_regex = re.compile('%SystemRoot%', flags=re.IGNORECASE)
		windir_regex = re.compile('%windir%', flags=re.IGNORECASE)
		programfiles_regex = re.compile('%ProgramFiles%', flags=re.IGNORECASE)
		system32_regex = re.compile('system32', flags=re.IGNORECASE)

		env_var_windir = os.getenv('windir')
		env_var_programfiles = os.getenv('ProgramFiles')
		env_var_systemroot = os.getenv('SystemRoot')
		env_var_systemdrive = os.getenv('SystemDrive')
		env_var_hostname = os.getenv('COMPUTERNAME')

		env_machine = platform.machine()

		zip_nb_files = 1
		zip_nb_errors = 0
		
		xor_key = 0x42
		if args.key:
			xor_key = int(args.key)

		homedirs_path = []
		binaries_extension = ['exe', 'com', 'dll', 'scr']

		if env_var_hostname is None:
			env_var_hostname = 'UnspecifiedHostname'
		
		debug_date = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
		debug_filename = 'FECT_' + env_var_hostname + '_' + debug_date + '.txt'

		try:
			print '[*] Creating the debug log file: ' + debug_filename
			g_debug_filehandle = open(debug_filename, 'w')
		except:
			print '[!] Error creating the debug file: ' + debug_filename 
			g_debug_filehandle = None

		printandlog('[*] FECT Log\r\n[*] Hostname: ' + env_var_hostname + '\r\n[*] Date: ' + debug_date + '\r\n[*] Autorunsc\'s options: ' + autorunsc_options)

		printandlog('[*] netstat -an')
		netstat_results = subprocess.check_output('netstat -an', stderr=subprocess.STDOUT, universal_newlines=True)
		printandlog(netstat_results)

		printandlog('[*] ipconfig /displaydns')
		ipconfig_results = subprocess.check_output('ipconfig /displaydns', stderr=subprocess.STDOUT, universal_newlines=True)
		printandlog(ipconfig_results)
		
		try:
			with open('autorunsc.exe', 'wb') as f:
				printandlog('[*] Writing autorunsc.exe')
				f.write(g_autorunsc_exe_hex_encoded.decode('hex'))
		except:
			printandlog('[!] Error writing tmp_autorunsc.exe binary')

		try:
			autorunsc_csv_results = subprocess.check_output('autorunsc.exe ' + autorunsc_options + ' -\"accepteula\"', stderr=subprocess.STDOUT, universal_newlines=True)
			autorunsc_csv_results = autorunsc_csv_results.decode('utf-16').encode('utf-8')
			
			file_paths = path_regex.findall(autorunsc_csv_results)
			file_paths_with_var = path_with_var_regex.findall(autorunsc_csv_results)
			file_paths_with_var_replaced = []

			for file_path_with_var in file_paths_with_var:
				match = systemroot_regex.search(file_path_with_var)
				if match:
					file_paths_with_var_replaced.append(re.sub(systemroot_regex, env_var_systemroot, file_path_with_var))
				match = programfiles_regex.search(file_path_with_var)
				if match:
					file_paths_with_var_replaced.append(re.sub(programfiles_regex, env_var_programfiles, file_path_with_var))
				match = windir_regex.search(file_path_with_var)
				if match:
					file_paths_with_var_replaced.append(re.sub(windir_regex, env_var_systemroot, file_path_with_var))
			
			file_paths = file_paths + file_paths_with_var_replaced
			
			if env_machine == "AMD64":			# Don't be fooled by the WoW Effect... http://cert.at/static/downloads/papers/cert.at-the_wow_effect.pdf
				printandlog('[*] I\'m running on a 64bits OS. I must replace the System32 path to circumvent the WoW effet')
				wow_file_paths = []
				for file_path in file_paths:
					match = system32_regex.search(file_path)
					if match:
						wow_file_paths.append(re.sub(system32_regex, 'Sysnative', file_path))					# http://msdn.microsoft.com/en-us/library/windows/desktop/aa384187(v=vs.85).aspx
				file_paths = wow_file_paths

			nb_paths = str(len(file_paths))

			printandlog('[*] ' + nb_paths + ' binaries paths found')
			try:
				with open('autorunsc_csv_results.csv', 'w+') as acr:
					acr.write(autorunsc_csv_results)

			except IOError as e:
				printandlog('[!] Error: ' + e.strerror)
			except:
				printandlog('[!] Unexpected error: ' + sys.exc_info()[0])

		except subprocess.CalledProcessError as e:
			printandlog('[!] Error executing autorunsc: ' + str(e.output))

		ZipName = 'FECT_logs_and_binaries_' + env_var_hostname + '_' + debug_date + '.zip'
		XoredZipName = 'FECT_logs_and_binaries_' + env_var_hostname + '_' + debug_date + '.zip.xor'

		try:
			with zipfile.ZipFile(ZipName, 'w', allowZip64=True) as zf:
				zf.write('autorunsc_csv_results.csv')
				for file_path in file_paths:
					c_md5 = chunkedmd5(file_path)
					if c_md5 != '':
						if c_md5 not in g_md5s:
							g_md5s.append(c_md5)
							printandlog('[+] [' + str(zip_nb_files) + '/' + nb_paths + '] Adding ' + file_path + ' ' + c_md5)
							try:
								zf.write(file_path)
								zip_nb_files += 1
							except (IOError, WindowsError) as e:
								printandlog('[!] I/O Error adding ' + file_path + ': ' + e.strerror)
								zip_nb_errors += 1
								pass
							except:
								printandlog('[!] Error adding ' + file_path + ': ' + str(sys.exc_info()[0]) + str(sys.exc_info()[1]) + str(sys.exc_info()[2]))
								zip_nb_errors += 1
								pass
						else:
							printandlog('[+] ' + file_path + '\'s md5 (' + c_md5 + ') already added' )

				if os.path.isdir(os.path.join(env_var_systemdrive, os.sep, 'Documents and Settings')):
					homedirs_path.append(os.path.join(env_var_systemdrive, os.sep, 'Documents and Settings'))
				if os.path.isdir(os.path.join(env_var_systemdrive, os.sep, 'Users')):
					homedirs_path.append(os.path.join(env_var_systemdrive, os.sep, 'Users'))
				
				for homedir_path in homedirs_path:
					printandlog('[*] Users\' homes path: ' + homedir_path)
					for Root, Dirs, Files in os.walk(homedir_path):
						for File in Files:
							if File[-3:] in binaries_extension:
								file_path = os.path.join(Root, File)
								c_md5 = chunkedmd5(file_path)
								if c_md5 != '':
									if c_md5 not in g_md5s:
										g_md5s.append(c_md5)
										printandlog('[+] Adding ' + file_path + ' ' + c_md5)
										try:
											zf.write(file_path)
											zip_nb_files += 1
										except (IOError, WindowsError) as e:
											printandlog('[!] I/O Error adding ' + file_path + ': ' + e.strerror)
											zip_nb_errors += 1
											pass
										except:
											printandlog('[!] Error adding ' + file_path + ': ' + str(sys.exc_info()[0]) + ' ' + str(sys.exc_info()[1]) + ' ' + str(sys.exc_info()[2]))
											zip_nb_errors += 1
											pass
									else:
										printandlog('[+] ' + file_path + '\'s md5 (' + c_md5 + ') already added' )

				printandlog('\n[+] ' + str(zip_nb_files) + ' files added to the zip archive with ' + str(zip_nb_errors) + ' errors')

		except IOError as e:
			printandlog('[!] Zip Error({0}): {1}'.format(e.errno, e.strerror))
		except:
			printandlog('[!] Zip Unexpected error: ' + str(sys.exc_info()[0]) + ' ' + str(sys.exc_info()[1]) + ' ' + str(sys.exc_info()[2]))

		for md5_ in g_md5s:
			printandlog(md5_)
		try:
			printandlog('[*] Removing the temporary files')
			os.remove('autorunsc.exe')			
			os.remove('autorunsc_csv_results.csv')

		except:
			printandlog('[!] Error removing the temporary files. You have to do the cleaning by yourself.')

		if g_debug_filehandle:
			g_debug_filehandle.close()
		try:
			with zipfile.ZipFile(ZipName, 'a', allowZip64=True) as zf:
				zf.write(debug_filename)
		except IOError as e:
			print '[!] Ziping Error({0}): {1}'.format(e.errno, e.strerror)
		except:
			print '[!] Ziping Unexpected error: ' + str(sys.exc_info()[0]) + ' ' + str(sys.exc_info()[1] + ' ' + str(sys.exc_info()[2]))
	
		print '[*] Xoring the zip archive to protect it from AV'
		
		bytes_ = None

		try:
			zipin = open(ZipName, 'rb')
			zipout = open(XoredZipName, 'wb')
			
			block = 10000000
			
			bytes_ = zipin.read(block)
			while bytes_ != "":
				print '[*] Reading and Xoring... ' + str(len(bytes_)) + ' bytes'
				bytearray_ = bytearray(bytes_)
				bytearray_len = len(bytearray_)

				for i in xrange(bytearray_len):
					bytearray_[i] ^= xor_key
				
				zipout.write(bytearray_)

				bytes_ = zipin.read(block)

		except IOError as e:
			print '[!] Xoring Error({0}): {1}'.format(e.errno, e.strerror)
		except:
			print '[!] Xoring Unexpected error: ' + str(sys.exc_info()[0]) + ' ' + str(sys.exc_info()[1] + ' ' + str(sys.exc_info()[2]))
		finally:
			zipin.close()
			zipout.close()

		try:
			print '[*] Removing the debug log file and the original zip file'
			os.remove(ZipName)
			os.remove(debug_filename)			
		except:
			print '[!] Error removing a file. You have to do the cleaning by yourself.'

	else:
		print '[!] Error, the script has to be run with Administrator privileges (Right click on me -> Run as an Administrator)'

if __name__ == '__main__':
	Main()