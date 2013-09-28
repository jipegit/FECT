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

__version__ = '0.2'

# Put your hex-encoded autorunsc.exe here
autorunsc_exe_hex_encoded = ''

debug_filehandle = None

def printandlog(logstr):
	''' print and log if the log handle is available '''
	
	global debug_filehandle

	print logstr
	if debug_filehandle is not None:
		debug_filehandle.write(logstr + '\r\n')

def Main():
	''' main '''
	
	global debug_filehandle
	
	parser = argparse.ArgumentParser(description='Use Microsoft autorunsc to identify binaries launched at windows startup and zip all the binaries to an archive')
	parser.add_argument('-a', '--autorunsc_options', help='Wrapped options passed to autorunsc. E.g.: pyAutoruns.py -a \"-b -s -c -f\" Double quotes are Mandatory. -c is Mandatory as well.')
	parser.add_argument('-k', '--key', help='The key to xor the zip archive with. Default if 0x42')

	args = parser.parse_args()

	print '\n[*] Fast Evidence Collector Toolkit v' + __version__ + ' by @Jipe_\n'

	if autorunsc_exe_hex_encoded == '':
		print '[!] Error autorunsc hex-encoded binary is missing'
		raise

	if shell.IsUserAnAdmin():
		print '[*] That\'s fine, I\'m running with Administrator privileges'

		autorunsc_options = '-a -c -m -f'	#All entries with the respective hashes, except the one from Microsoft, with a CSV output 

		if args.autorunsc_options:
			autorunsc_options = args.autorunsc_options

		path_regex = re.compile('\"([a-z]:[\w\\\s-]+?\.\w{3})[\s\"]{1}', flags=re.IGNORECASE)			#match normal paths
		path_with_var_regex = re.compile('\"(%\w+%[\w\\\s-]+?\.\w{3})[\s\"]{1}', flags=re.IGNORECASE)	#match paths using an %environementvariables%

		systemroot_regex = re.compile('%SystemRoot%', flags=re.IGNORECASE)
		windir_regex = re.compile('%windir%', flags=re.IGNORECASE)
		programfiles_regex = re.compile('%ProgramFiles%', flags=re.IGNORECASE)

		env_var_windir = os.getenv('windir')
		env_var_programfiles = os.getenv('ProgramFiles')
		env_var_systemroot = os.getenv('SystemRoot')
		env_var_systemdrive = os.getenv('SystemDrive')
		env_var_hostname = os.getenv('COMPUTERNAME')

		zip_nb_files = 1
		zip_nb_errors = 0
		
		xor_key = 0x42
		if args.key:
			xor_key = int(args.key)

		homedirs_path = None
		binaries_extension = ['exe', 'com', 'dll', 'scr']

		if env_var_hostname is None:
			env_var_hostname = 'UnspecifiedHostname'
		
		debug_date = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
		debug_filename = 'FECT_' + env_var_hostname + '_' + debug_date + '.txt'

		try:
			print '[*] Creating the debug log file: ' + debug_filename
			debug_filehandle = open(debug_filename, 'w')
		except:
			print '[!] Error creating the debug file: ' + debug_filename 
			debug_filehandle = None

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
				f.write(autorunsc_exe_hex_encoded.decode('hex'))
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
			
			file_paths_with_var_replaced
			file_paths = file_paths + file_paths_with_var_replaced
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
			with zipfile.ZipFile(ZipName, 'w') as zf:
				zf.write('autorunsc_csv_results.csv')
				for file_path in file_paths:
					printandlog('[+] [' + str(zip_nb_files) + '/' + nb_paths + '] Adding ' + file_path)
					try:
						zf.write(file_path)
						zip_nb_files += 1
					except (IOError, WindowsError) as e:
						printandlog('[!] I/O Error adding ' + file_path + ': ' + e.strerror)
						zip_nb_errors += 1
						pass
					except:
						printandlog('[!] Error adding ' + file_path + ': ' + str(sys.exc_info()[0]))
						zip_nb_errors += 1
						pass

				if os.path.isdir(os.path.join(env_var_systemdrive, os.sep, 'Documents and Settings')):
					homedirs_path = os.path.join(env_var_systemdrive, os.sep, 'Documents and Settings')
				elif os.path.isdir(os.path.join(env_var_systemdrive, os.sep, 'Users')):
					homedirs_path = os.path.join(env_var_systemdrive, os.sep, 'Users')
				else:
					printandlog('[!] Error determining users\' directory')

				if homedirs_path:
					printandlog('[*] Users\' homes path: ' + homedirs_path)
					for Root, Dirs, Files in os.walk(homedirs_path):
						for File in Files:
							if File[-3:] in binaries_extension:
								file_path = os.path.join(Root, File)
								try:
									printandlog('[+] Adding ' + file_path)
									zf.write(file_path)
									zip_nb_files += 1
								except (IOError, WindowsError) as e:
									printandlog('[!] I/O Error adding ' + file_path + ': ' + e.strerror)
									zip_nb_errors += 1
									pass
								except:
									printandlog('[!] Error adding ' + file_path + ': ' + str(sys.exc_info()[0]))
									zip_nb_errors += 1
									pass

				printandlog('\n[+] ' + str(zip_nb_files) + ' files added to the zip archive with ' + str(zip_nb_errors) + ' errors')

		except IOError as e:
			printandlog('[!] Zip Error({0}): {1}'.format(e.errno, e.strerror))
		except:
			printandlog('[!] Zip Unexpected error: ' + str(sys.exc_info()[0]) + ' ' + str(sys.exc_info()[1]) )

		try:
			printandlog('[*] Removing the temporary files')

			os.remove('autorunsc.exe')			
			os.remove('autorunsc_csv_results.csv')

		except:
			printandlog('[!] Error removing the temporary files. You have to do the cleaning by yourself.')

		if debug_filehandle:
			debug_filehandle.close()
		try:
			with zipfile.ZipFile(ZipName, 'a') as zf:
				zf.write(debug_filename)
		except IOError as e:
			print '[!] Ziping Error({0}): {1}'.format(e.errno, e.strerror)
		except:
			print '[!] Ziping Unexpected error: ' + str(sys.exc_info()[0]) + ' ' + str(sys.exc_info()[1])
	
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

				for i in range(bytearray_len):
					bytearray_[i] ^= xor_key
				
				zipout.write(bytearray_)

				bytes_ = zipin.read(block)

		except IOError as e:
			print '[!] Xoring Error({0}): {1}'.format(e.errno, e.strerror)
		except:
			print '[!] Xoring Unexpected error: ' + str(sys.exc_info()[0]) + ' ' + str(sys.exc_info()[1])
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