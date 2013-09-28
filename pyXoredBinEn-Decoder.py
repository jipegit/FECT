# -*- encoding: utf-8 -*-
#
#  FECT/pyXoredBinEn-Decoder.py
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

	parser = argparse.ArgumentParser(description='[En|De]code a xored binary')
	parser.add_argument('-i', '--input', help='Input filename')
	parser.add_argument('-o', '--output', help='Output filename')
	parser.add_argument('-k', '--key', help='optional Key (Default is 0x42)')
	
	args = parser.parse_args()

	xor_key = 0x42

	if args.input and args.output:
		bytes = None

		if args.key:
			xor_key = int(args.key)

		print '[*] ' + args.input + ' -> ' + args.output
		
		try:
			filein = open(args.input, 'rb')
			fileout = open(args.output, 'wb')
			block = 10000000
			bytes_ = filein.read(block)
		    
			while bytes_ != "":
				print '[*] Reading... ' + str(len(bytes_)) + ' bytes to xor'
				bytearray_ = bytearray(bytes_)
				bytearray_len = len(bytearray_)

				for i in range(bytearray_len):
					bytearray_[i] ^= xor_key
				
				fileout.write(bytearray_)

				bytes_ = filein.read(block)

		except IOError as e:
			print '[!] Error({0}): {1}'.format(e.errno, e.strerror)
		except:
			print '[!] Unexpected error: ' + str(sys.exc_info()[0]) + ' ' + str(sys.exc_info()[1])
		finally:
			filein.close()
			fileout.close()	
	else:
		print '[!] Error: missing parameter (-i or -o)'

if __name__ == '__main__':
	Main()