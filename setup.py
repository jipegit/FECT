# -*- encoding: utf-8 -*-
#
#  FECT/setup.py
#  
#  Author: Jean-Philippe Teissier ( @Jipe_ ) 
#    
#  This work is licensed under the GNU General Public License
#
#  Dependencies: py2exe
#

# ...
# ModuleFinder can't handle runtime changes to __path__, but win32com uses them
# See. http://www.py2exe.org/index.cgi/win32com.shell	#LeLibre...

try:
    # py2exe 0.6.4 introduced a replacement modulefinder.
    # This means we have to add package paths there, not to the built-in
    # one.  If this new modulefinder gets integrated into Python, then
    # we might be able to revert this some day.
    # if this doesn't work, try import modulefinder
    try:
        import py2exe.mf as modulefinder
    except ImportError:
        import modulefinder
    import win32com, sys
    for p in win32com.__path__[1:]:
        modulefinder.AddPackagePath("win32com", p)
    for extra in ["win32com.shell"]: #,"win32com.mapi"
        __import__(extra)
        m = sys.modules[extra]
        for p in m.__path__[1:]:
            modulefinder.AddPackagePath(extra, p)
except ImportError:
    # no build path setup, no worries.
    pass

from distutils.core import setup
import py2exe
import sys

# Just in case...
if len(sys.argv) == 1:
    sys.argv.append("py2exe")

setup(
	console=[{
        'script': 'FECT.py',
        'icon_resources': [(0, 'FECT.ico')]
        }],

	options={'py2exe':{
						'includes': ['pythoncom'],
						'includes': ['pywintypes'],
						'includes': ['win32'],
						'includes': ['win32com'],
						'includes': ['win32api'],
						'bundle_files': 1
					}
	},
	zipfile = None,
	name = 'Fast Evidence Collector Toolkit',
	version = '0.3.3',
	description = 'Fast Evidence Collector Toolkit',
	author = '@Jipe_',
	author_email = 'jipedevs_@_gmail_com',
	url = 'https://github.com/jipegit/FECT',
  )
