# Fast Evidence Collector Toolkit

Fast Evidence Collector Toolkit is an incident response toolkit to collect evidences on a suspicious windows computer.

It uses Microsoft autorunsc to identify binaries launched at windows startup and zip all the binaries to an archive.
autorunsc.exe v11.70 (6677b6017e5d470cf99ef60d1802bccc) is hex encoded and embedded in FECT.py.

## Author

Jean-Philippe Teissier - @Jipe_ 

## How to install

Just copy all files from github

## Dependencies

* pywin32 - http://sourceforge.net/projects/pywin32/files/
* py2exe - http://www.py2exe.org/

## How to build

python setup py2exe

## How to run

Just double click on it :)

Default options passed to autorunsc are '-a -c -m -f' i.e. all entries with the respective hashes, except the one from Microsoft, output format is CSV.

FECT also acts as a wrapper for autorunsc. You can pass any specific options you want by using the -a option.
E.g.: FECT.py -a \"-b -s -c -f\"

Beware: double quotes are Mandatory. -c is mandatory as well.

## Changelog
### 0.1
 * Initial Release

## TODO
 * n/a

## License

FECT
Copyright (C) 2013 Jean-Philippe Teissier

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Microsoft autorunsc has his own EULA. By using FECT you DO ACCEPT it. 
See. http://technet.microsoft.com/en-us/sysinternals/bb963902.aspx
