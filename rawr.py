#!/usr/bin/env python

####
#
#       RAWR - Rapid Assessment of Web Resources
#               Written 2012 by Adam Byers  (@al14s)
#                   al14s@pdrcorps.com
#
#
#                      Romans 5:6-8
#
#    See the file 'docs/LICENSE' for copying permission.
#
####

import os
import re
import sys
import shutil
import tarfile
import httplib
import optparse
from time import sleep
from glob import glob
from subprocess import call
from httplib import HTTPConnection
from platform import system
from datetime import datetime

# Set a few static variables
timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
scriptpath = os.path.dirname(os.path.realpath(__file__))
logdir = os.path.realpath("log_%s_rawr" % timestamp)

from lib.constants import *
from lib.banner import *
from conf.settings import *
from lib.functions import *

# pull&parse our commandline args
parser = optparse.OptionParser(usage=usage, version=VERSION)
parser.add_option('-a', help='Include all open ports in .csv, not just web interfaces.', dest='allinfo', action='store_true', default=False)
parser.add_option('-f', help='NMap|Nessus|Nexpose|Qualys xml or dir from which to pull files.', dest='xmlfile')
parser.add_option('-i', help="Target an input list.  [NMap format] [can't be used with -n]", dest='nmap_il')
parser.add_option('-n', help="Target the specified range or host.  [NMap format]", dest='nmaprng')
parser.add_option('-p', help="Specify port(s) to scan.   [default is '80,443,8080,8088']", dest='ports')
parser.add_option('-s', help='Specify a source port for the NMap scan.', dest='sourceport', type='int')
parser.add_option('-t', help='Set a custom NMap scan timing.   [default is 4]', dest='nmapspeed', type='int')
parser.add_option('-y', help='', dest='y', action='store_true', default=False)
parser.add_option('--sslv', help='Assess the SSL security of each target.  [considered intrusive]', dest='sslopt', action='store_true', default=False)

group = optparse.OptionGroup(parser, "Enumeration Options")
group.add_option('-b', help='Use Bing to gather external hostnames. (good for shared hosting)', dest='bing_dns', action='store_true', default=False)
group.add_option('-o', help="Make an 'OPTIONS' call to grab the site's available methods.", dest='getoptions', action='store_true', default=False)
group.add_option('-r', help='Make an additional web call to get "robots.txt"', dest='getrobots', action='store_true', default=False)
group.add_option('--downgrade', help='Make requests using HTTP 1.0', dest='ver_dg', action='store_true', default=False)
group.add_option('--noss', help='Disable screenshots.', dest='noss', action='store_true', default=False)
group.add_option('--spider', help="Enumerate all urls in target's HTML, create site layout graph.  Will record but not follow links outside of the target's domain.  Creates a map (.png) for that site in the <logfolder>/maps folder.", dest='crawl', action='store_true', default=False)
parser.add_option_group(group)

group = optparse.OptionGroup(parser, "Output Options")
group.add_option('-d', help='Directory in which to create log folder [default is "./"]', dest='logdir')
group.add_option('-q', '--quiet', help="Won't show splash screen.", dest='quiet', action='store_true', default=False)
group.add_option('-z', help='Compress log folder when finished.', dest='compress_logs', action='store_true', default=False)
group.add_option('--json', help='stdout will include only JSON strings. Log folders and files are created normally.', dest='json', action='store_true', default=False)
group.add_option('--json-minimal', help='The only output of this script will be JSON strings to stdout.', dest='json_min', action='store_true', default=False)
parser.add_option_group(group)

group = optparse.OptionGroup(parser, "Report Options")
group.add_option('-e', help='Exclude default username/password data from output.', dest='defpass', action='store_true', default=True)
group.add_option('--logo', help='Specify a logo file for the HTML report.', dest='logo')
group.add_option('--title', help='Specify a custom title for the HTML report.', dest='title')
parser.add_option_group(group)

group = optparse.OptionGroup(parser, "Update Options")
group.add_option('-u', help='Check for newer version of IpToCountry.csv and defpass.csv.', dest='update', action='store_true', default=False)
group.add_option('-U', help='Force update of IpToCountry.csv and defpass.csv.', dest='forceupdate', action='store_true', default=False)
group.add_option('--check-install', help="Check for newer IpToCountry.csv and defpass.csv. Check for presence of NMap and its version. Check for presence of phantomJS, prompts if installing.", dest='checkinstall', action='store_true', default=False)
group.add_option('--force-install', help="Force update - IpToCountry.csv, defpass,csv, phantomJS.  Also check for presence of NMap and its version.", dest='forceinstall', action='store_true', default=False)
parser.add_option_group(group)

(opts, args) = parser.parse_args()

if opts.y: 
	import random;i=words.split(':'); e="%s %s of %s %s"%(random.choice(i[0].split(',')),random.choice(i[1].split(',')),random.choice(i[2].split(',')),random.choice(i[3].split(','))); e=(" "*((18-len(e)/2)))+e+(" "*((18-len(e)/2))); print banner.replace("  Rapid Assessment of Web Resources ",e[0:36]); sys.exit()

# Remove the big dinosaur...  :\
if not opts.quiet:
	print banner

if len(sys.argv) ==99:
	print usage
	sys.exit(2)

# Look for PhantomJS if needed
if inpath("phantomjs"):
	pjs_path = "phantomjs"

elif os.path.exists("%s/data/phantomjs/bin/phantomjs" % scriptpath):
	pjs_path = "%s/data/phantomjs/bin/phantomjs" % scriptpath

elif system() in "CYGWIN|Windows" and inpath("phantomjs.exe"):
	pjs_path = "phantomjs.exe"

elif system() in "CYGWIN|Windows" and (os.path.exists("%s/data/phantomjs/phantomjs.exe" % scriptpath)):
	pjs_path = "%s/data//phantomjs/phantomjs.exe" % scriptpath

else:
	pjs_path = ""


if (opts.update or opts.forceupdate):
	if opts.update:
		update(False, False, pjs_path, scriptpath)

	else:
		update(True, False, pjs_path, scriptpath)

if opts.forceinstall:
	update(True, True, pjs_path, scriptpath)

elif opts.checkinstall:
	update(False, True, pjs_path, scriptpath)


if pjs_path == "" and not opts.noss:
	print "  !! phantomJS not found in $PATH or in RAWR folder.  \n\n\tTry running 'rawr.py --check-install'\n\n  !! Exiting... !!\n\n"
	sys.exit(1)


# sanity checks
if (opts.nmap_il and opts.nmaprng) or (opts.xmlfile and (opts.nmap_il or opts.nmaprng)):
	parser.error("Can't use -f, -i, or -n in the same command.")
	sys.exit(1)

# Take a look at out inputs
if opts.xmlfile:
	if not os.path.exists(os.path.abspath(opts.xmlfile)): 
		print "Unable to locate \n\t[%s]. =-\n" % opts.xmlfile
		sys.exit(1)

	if os.path.isdir(opts.xmlfile):
		for f in glob("%s/*.xml" % opts.xmlfile):
			files.append(os.path.realpath(f))

		if not files:
			print "No .xml files in \n\t[%s]. =-\n" % opts.xmlfile
			sys.exit(1)

	else: 
		xmlfile = True
		files = [os.path.realpath(opts.xmlfile)]

elif opts.nmap_il or opts.nmaprng:
	if opts.nmap_il:
		if os.path.exists(opts.nmap_il): 
			nmap_il = os.path.realpath(opts.nmap_il)
		else:
			print "Unable to locate file \n\t[%s]. =-\n" % opts.nmap_il
			sys.exit(1)

	else:
		nmaprng = opts.nmaprng

	if opts.ports:
		if str(opts.ports).lower() == "fuzzdb":
			ports = fuzzdb

		elif str(opts.ports).lower() == "all":
			ports = "1-65535"

		else:
			ports = str(opts.ports)

	if opts.nmapspeed:
		try:
			if 6 > int(opts.nmapspeed) > 0:
				nmapspeed = opts.nmapspeed
			else:
				raise()
		except:
			print "\n  -= Scan Timing (-t) must be numeric and 1-5 =-\n"
			sys.exit(1)

else:
	print usage + "\n\n\n  -= No input specified. =-\n"
	sys.exit(1)


if opts.logdir:
	# redefine logdir based on user request
	logdir = os.path.realpath(opts.logdir) + "/log_%s_rawr" % timestamp

if opts.logo:
	if os.path.exists(os.path.abspath(opts.logo)):
		from PIL import Image
		i = Image.open(os.path.abspath(opts.logo)).size
		if i[0] > 400 or i[1] > 60:
			print "[ warning ]  The specified logo may not show up correctly.\n\tA size no larger than 400x60 is recommended.\n"

		logo_file = os.path.realpath(opts.logo)

	else:
		print "\t-= Unable to locate logo file \n\t[%s]. =-\n" % opts.logo
		sys.exit(1)

if opts.title:
	if len(opts.title) > 60:
		print "[warning] The title specified might not show up properly."

	report_title = opts.title


# Create the log directory if it doesn't already exist.
if not os.path.exists(logdir): 
	os.makedirs(logdir)
	newdir = True
else:
	newdir = False

logfile = "%s/rawr_%s.log" % (logdir, timestamp)	
os.chdir(logdir)


# Check for the list of default passwords
if opts.defpass:
	if os.path.exists("%s/%s" % (scriptpath, DEFPASS_FILE)): 
		writelog("\n   -= Located defpass.csv =-\n", logfile)

	else:
		writelog("\n   -= Unable to locate %s. =-\n" % DEFPASS_FILE, logfile)
		choice = raw_input("\tContinue without default password info? [Y|n] ").lower()
		defpass = False
		if (not choice in "yes") and choice != "": 
			print "\n   !! Exiting... !!\n\n"
			sys.exit(2)


if opts.ver_dg:
	# downgrade to HTTP 1.0
	httplib.HTTPConnection._http_vsn = 10
	httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'


msg = "\nStarted RAWR : %s\n     cmdline : %s\n\n" % (timestamp, " ".join(sys.argv))
open("%s/rawr_%s.log" % (logdir, timestamp),'a').write(msg)
writelog("\n  -= Log Folder created : %s =-\n" % logdir, logfile)


# Create a list called 'files', which contains filenames of all our .xml sources.
if opts.nmap_il or opts.nmaprng:
	files = []
	# Run NMap to provide discovery [xml] data
	if opts.nmap_il != "" or (re.match('^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}(:[0-9]{1,5})?(\/.*)?$', opts.nmaprng) or (re.match('^((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]{1}){1}){0,}|\*)\.(((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}){0,}|\*)\.){2}((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}){0,}|\*|([0]{1}\/(8|9|[1-2]{1}[0-9]{1}|30|31|32){1})){1}$', opts.nmaprng) and not re.match('([-][0-9]{1,3}[-])|(([,-].*[/]|[/].*[,-])|([*].*[/]|[/].*[*]))', opts.nmaprng) and not re.match('([-][0-9]{1,3}[-])|(([,-].*[/]|[/].*[,-])|([*].*[/]|[/].*[*]))', opts.nmaprng))):
		# ^^ check for valid nmap input (can use hostnames, subnets (ex. 192.168.0.0/24), stars (ex. 192.168.*.*), and split ranges (ex. 192.168.1.1-10,14))
		if not (inpath("nmap") or inpath("nmap.exe")):
			writelog("  !! NMap not found in $PATH.  Exiting... !!\n\n", logfile)
			sys.exit(1)

		writelog("  -= Beginning NMap Scan =-", logfile)

		# Build the NMap command args
		cmd = ["nmap","-Pn"]

		if opts.sourceport:
			cmd += "-g", str(opts.sourceport)

		sslscripts = "--script=ssl-cert"
		if opts.sslopt:
			sslscripts += ",ssl-enum-ciphers"

		cmd += "-p", ports ,"-T%s" % nmapspeed, "-vv", "-sV", sslscripts, "-oA", "rawr_" + timestamp, "--open"

		if opts.nmap_il: 
			cmd += "-iL", opts.nmap_il
		else:
			cmd.append(opts.nmaprng)

		writelog('  Running > ' + " ".join(cmd), logfile)

		try:
			with open("%s/rawr_%s.log" % (logdir, timestamp),'ab') as log_pipe:
				ret = subprocess.call(cmd, stdout=None, stderr=log_pipe)
		except KeyboardInterrupt: 
			writelog("\n\n **  Scanning Halted (ctrl+C).  Exiting!   ** \n\n", logfile)
			sys.exit(2)
		except Exception, ex: 
			writelog("\n\n **  Error in scan - %s   ** \n\n" % ex, logfile)
			sys.exit(2)

		if ret != 0:
			writelog("\n\n", logfile)
			sys.exit(1)

		files = ["rawr_%s.xml" % timestamp]

	else:
		writelog("\n  !! Specified address range is invalid. !!\n", logfile)
		sys.exit(1)

elif newdir:
	# Move the user-specified xml file(s) into the new log directory
	old_files = files
	files = ""
	for filename in old_files:
		shutil.copyfile(filename,"./"+os.path.basename(filename))
		files += filename + ","

	files = files.strip(",").split(",")
		

# Look for and copy any images from previous scans
if not newdir and not (glob("*.png") or glob("images/*.png")): 
	writelog("\n ** No thumbnails found in [%s/]\n\t\t or in [.%s/images/]. **\n" % (os.getcwd(), os.getcwd()), logfile)
	writelog("\tWill take website screenshots during the enumeration. ", logfile)
else: 
	if not os.path.exists("images"):
		os.mkdir("images")

	for filename in glob("*.png"):
		newname = filename.replace(":","_")
		os.rename(filename, "./images/%s" % (newname))


for filename in files:
	writelog("[>] Parsing : \n\t%s\n   for web hosts...\n" % filename, logfile)
	try:
		r = etree.parse(filename)

		if len(r.xpath('//NexposeReport')) > 0:
			targets = parseNexposeXML(r)

		if len(r.xpath('//ASSET_DATA_REPORT')) > 0:
			targets = parseQualysXML(r)

		elif len(r.xpath('//NessusClientData_v2')) > 0:
			targets = parseNessusXML(r)
					
		elif len(r.xpath('//nmaprun')) > 0:
			targets = parseNMapXML(r)

		else:
			writelog("    [!] Unrecognized file format.  [ %s ]" % filename, logfile)
			continue

		for target in targets: 
			q.put(target)

	except Exception, ex:
		writelog("\n\n    [!] Unable to parse %s !\n\t\t Error: %s\n\n" % ( filename, ex ), logfile)


	writelog("    [>] Found [ %s ] web hosts in \n\t%s" % ( q.qsize(), filename ), logfile)

	data = None


# Begin processing any hosts found
if q.qsize() > 0:
	# Create the folder for html resource files
	if not os.path.exists("./html_res"): 
		os.makedirs("./html_res")
	shutil.copy("%s/data/jquery.js" % scriptpath, "./html_res/jquery.js")
	shutil.copy("%s/data/style.css" % scriptpath, "./html_res/style.css")
	shutil.copy("%s/data/report_template.html" % scriptpath, 'index_%s.html' % timestamp)

	# Make the link to NMap XML in our HTML report
	if len(files) == 1:
		if opts.xmlfile:
			fname = os.path.basename(files[0])
		else:
			fname = "rawr_%s.xml" % timestamp

		filedat = open('index_%s.html' % timestamp).read()
		filedat = filedat.replace( '<!-- REPLACEWITHLINK -->', fname )
		filedat = filedat.replace( '<!-- REPLACEWITHDATE -->', datetime.now().strftime("%b %d, %Y") )
		filedat = filedat.replace( '<!-- REPLACEWITHTITLE -->', report_title )
		if opts.nmap_il:
			report_range = str(opts.nmap_il)
			
		elif opts.nmaprng != "":
			report_range = str(opts.nmaprng)
			
		else:
			if len(files) > 1:
				report_range = "%s files" % len(files)

			else:
				report_range = str(", ".join(files)[:40])

		
		filedat = filedat.replace( '<!-- REPLACEWITHRANGE -->', report_range )
		filedat = filedat.replace( '<!-- REPLACEWITHTIMESTAMP -->', timestamp )
		filedat = filedat.replace( '<!-- REPLACEWITHFLIST -->', flist )


		if opts.logo:
			shutil.copy(logo_file, "./html_res/")
			filedat = filedat.replace( '<!-- REPLACEWITHLOGO -->', ( '\n<img id="logo" src="./html_res/%s" />\n' % os.path.basename(logo_file) ) )

		open('index_%s.html' % timestamp,'w').write( filedat )

	for xmlfile in glob("rawr_*.xml"):
		if os.path.exists("%s/data/nmap.xsl" % scriptpath) and not os.path.exists("./nmap.xsl"): 
			shutil.copy("%s/data/nmap.xsl" % scriptpath,"./html_res/nmap.xsl")

			fileloc = re.findall(r'.*href="(.*)" type=.*', open(xmlfile).read())[0]
			filedat = open(xmlfile).read().replace(fileloc,'html_res/nmap.xsl')
			open(xmlfile,'w').write(filedat)

			writelog("\n  Copied nmap.xsl to %s\n\tand updated link in xml files.\n\n" % logdir, logfile)
		else: 
			writelog("\n  Unable to locate nmap.xsl.\n\n", logfile)

	if not os.path.exists("rawr_%s_serverinfo.csv" % timestamp):
		open("rawr_%s_serverinfo.csv" % timestamp, 'w').write(flist)

	writelog("\n   -= Getting info from server(s) =-\n", logfile)

	o = out_thread(logfile)
	o.daemon = True
	o.start()

	# Create the main worker pool and get them started
	for i in range(nthreads):
		t = sithread(timestamp, scriptpath, pjs_path, logdir, opts.bing_dns, opts.getoptions, opts.getrobots, opts.defpass, opts.crawl, opts.noss)
		threads.append(t)
		t.daemon = True
		t.start()

	# Wait until the queue is cleared or Ctrl+C is pressed
	try:
		while q.qsize() > 0:
			sleep(0.5)
			q.join()

	except KeyboardInterrupt:
		output.put("\n\n ******  Ctrl+C recieved - Stopping all threads.  ****** \n")

	# Queue is clear, tell the threads to close.
	output.put("\n\n   ** Finished.  Stopping Threads. **\n")
	for t in threads: 
		t.terminate = True

	# Close our output queue and clear our main objects
	output.join()
	output = None
	t = None
	o = None
	q = None
	
	# Add the data and ending tags to the HTML report
	open('index_%s.html' % timestamp, 'a').write("</div></body></html>")

	# Sort the csv on the specified column
	try: 
		i = flist.lower().split(", ").index(csv_sort_col)
		data_list = [line.strip() for line in open("rawr_%s_serverinfo.csv" % timestamp)]
		headers = data_list[0]
		data_list = data_list[1:]
		# Format IP adresses so we can sort them effectively
		if re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", line.split(",")[i]): 
			key = "%3s%3s%3s%3s" % tuple(line.split(",")[i].split('.'))

		else: 
			key = line.split(",")[i]

		data_list.sort(key= lambda line: (key), reverse=False)
		open("rawr_%s_serverinfo.csv" % timestamp, 'w').write(headers+"\n"+"\n".join(data_list))
	except:
		writelog("\n  --  '%s' was not found in the column list.  Skipping the CSV sort function.  --" % csv_sort_col, logfile)

	
	writelog("\n   ++ Report created in [%s/].  ++\n" % os.getcwd(), logfile)

	if opts.compress_logs:
		writelog("[>] Compressing logfile...\n", logfile)
		logdir = os.path.basename(os.getcwd())
		os.chdir("../")
		try:
			if  system() in "CYGWIN|Windows":
				shutil.make_archive(logdir, "zip", logdir)
				logdir_c = logdir + ".zip"
			else:
				tfile = tarfile.open(logdir+".tar", "w:gz")
				tfile.add(logdir)
				tfile.close()
				logdir_c = logdir + ".tar"

			print "   ++ Created  %s ++\n" % (logdir_c)
			if os.path.exists(logdir) and os.path.exists(logdir_c):
				shutil.rmtree(logdir)

		except Exception, ex:
			print "   !! Failed - %s\n" % ex

else:
	writelog("\n   !! No data returned. !! \n\n", logfile)


