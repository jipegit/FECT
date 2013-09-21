# -*- encoding: utf-8 -*-
#
#  FECT/pyBinHexEncoder.py
#  
#  Author: Jean-Philippe Teissier ( @Jipe_ ) 
#    
#  This work is licensed under the GNU General Public License
#

import binascii
import argparse
import sys

__version__ = '0.1'

def Main():
	''' main '''

	parser = argparse.ArgumentParser(description='Create a a hex encoded file of a binary')
	parser.add_argument('-i', '--input', help='Input filename')
	parser.add_argument('-o', '--output', help='Output filename')
	args = parser.parse_args()

	if args.input and args.output:
		bytes = None

		print '[*] ' + args.input + ' -> ' + args.output
		
		try:
			with open(args.input, 'rb') as f:
				bytes = f.read()
		except IOError as e:
			print '[!] Input Error: ' + e.strerror
		except:
			print '[!] Unexpected input error:', sys.exc_info()[0]	

		if bytes:
			hexdata = binascii.hexlify(bytes)

		try:
			with open(args.output, 'w+') as f2:
				f2.write(hexdata)
		except IOError as e:
			print '[!] Output Error: ' + e.strerror
		except:
			print '[!] Unexpected output error:', sys.exc_info()[0]	
	else:
		print '[!] Error: missing parameter (-i or -o)'

if __name__ == '__main__':
	Main()