# Fast Evidence Collector Toolkit

Fast Evidence Collector Toolkit is a light incident response toolkit to collect evidences on a suspicious Windows computer.
Basically it is intended to be used by non-tech savvy people working with a journeyman Incident Handler.

It uses Microsoft autorunsc to identify binaries launched at windows startup and zip all the binaries to a zip archive.
It looks for all .exe/.com/.dll/.scr in users' home directories and add them to the zipball.
It also logs the output of some interesting network commands.

Finally the zip archive is xored to evade from AV.

## Author

Jean-Philippe Teissier - @Jipe_ 

## Development status

*FECT is no longer maintained*

## How to install

Just copy all files from github

## Dependencies

* pywin32 - http://sourceforge.net/projects/pywin32/files/
* py2exe - http://www.py2exe.org/
* Microsoft Visual C runtime DLL See: http://www.py2exe.org/index.cgi/Tutorial#Step5

## How to build

Edit FECT.py and fill the autorunsc_exe_hex_encoded variable with a hex encoded version of the autorunsc binary.
You can use the provided pyBinHexEncoder.py script to generate it.

Then type:
python setup py2exe

## How to run

Just double click on it :) 

If there is not Microsoft Visual C runtime DLL on the suspicious computer, you must add the Microsoft.VC90.CRT directory (containing both Microsoft.VC90.CRT.manifest and msvcr90.dll) in the same directory as FECT.exe

Default options passed to autorunsc are '-a -c -m -f' i.e. all entries with the respective hashes, except the one from Microsoft, output format is CSV.

FECT also acts as a wrapper for autorunsc. You can pass any specific options you want by using the -a option.
E.g.: FECT.py -a \"-b -s -c -f\"

Beware: double quotes are Mandatory. -c is mandatory as well.

Finally use pyXoredBinEn-Decoder.py to unXor the zipball.

## Changelog
### 0.3.2
 * Autorunsc now scans all users' registry files

### 0.3.1
 * Handles zip archive > 2Gb 
 * memory footprint reduced

### 0.3
 * Circumvents the Wow effet. See. http://cert.at/static/downloads/papers/cert.at-the_wow_effect.pdf
 * Hashes all binaries and add all the md5s to the log file
 * deduplicates redundant binaries based on their md5
 * Parses both \Documents and Settings\ and \Users\

### 0.2
 * Searches all .exe/.com/.dll/.scr in users' home directories
 * A log file is now generated
 * The outputs of 'netstat -an' and 'ipconfig /displaydns' have been added to the log file
 * The zip file is XORed to evade from AV doing their job. The default key is 0x42

### 0.1
 * Initial Release

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

FECT.ico comes from http://openiconlibrary.sourceforge.net/ and has its own license
