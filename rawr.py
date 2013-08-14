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
import getopt
import tarfile
import httplib
from time import sleep
from glob import glob
from Queue import Queue
from socket import setdefaulttimeout
from subprocess import call
from httplib import HTTPConnection
from platform import system
from datetime import datetime
from xml.dom import minidom

# Set a few static variables
timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
scriptpath = os.path.dirname(os.path.realpath(__file__))
logdir = os.path.realpath("log_%s_rawr" % timestamp)

from lib.constants import *
from lib.banner import *
from conf.settings import *
from lib.functions import *


# Parse the arguments
try: 
	opts, args = getopt.getopt(sys.argv[1:], "abd:ef:hi:n:op:rs:t:quUyz", ["help","compress-logs","logo=","title=","downgrade","spider","sslv","check-install","force-install","quiet"])

except getopt.GetoptError, err: 
	print "%s\n%s\n\n\t!!   %s   !!\n\n" % (banner, usage, str(err))
	exit(2)

for o, a in opts:
	if o == ("-a"):
		allinfo = True

	elif o == ("-b"):
		bing_dns = True

	elif o == ("-d"):
		logdir = os.path.realpath(a) + "/log_%s_rawr" % timestamp

	elif o == ("--downgrade"):
		ver_dg = True

	elif o == ("-e"):
		defpass = False

	elif o == ("-f"):
		if not os.path.exists(os.path.abspath(a)): 
			print "Unable to locate [%s]. =-\n" % msg
			sys.exit(1)

		if os.path.isdir(a):
			for f in glob("%s/*.xml" % a):
				files.append(os.path.realpath(f))

			if not files:
				print "No .xml files in [%s]. =-\n" % msg
				sys.exit(1)

		else: 
			xmlfile = True
			files = [os.path.realpath(a)]

	elif o in ("-h", "--help"):
		print banner + usage + summary + examples
		sys.exit()

	elif o == ("-i"):
		if os.path.exists(a): 
			nmap_il = os.path.realpath(a)
		else:
			print "Unable to locate data source [%s]. =-\n" % msg
			sys.exit(1)

	elif o == ("--logo"):
		if os.path.exists(os.path.abspath(a)):
			from PIL import Image
			i = Image.open(os.path.abspath(a)).size
			if i[0] > 400 or i[1] > 60:
				print "[ warning ]  The specified logo may not show up correctly.\n\tA size no larger than 400x60 is recommended.\n"

			logo_file = os.path.realpath(a)

		else:
			print "Unable to locate logo file [%s]. =-\n" % msg
			sys.exit(1)

	elif o == ("-n"):
		nmaprng = a

	elif o == ("-o"):
		getoptions = True

	elif o == ("-p"):
		if a.lower() == "fuzzdb":
			ports = fuzzdb

		elif a.lower() == "all":
			ports = "1-65535"

		else:
			ports = a

	elif o == ("-u"):
		ckinstall = False
		upd = True
		force = False

	elif o == ("-U"):
		ckinstall = False
		upd = True
		force = True

	elif o == ("--check-install"):
		ckinstall=True
		upd = True
		force = False

	elif o == ("--force-install"):
		ckinstall = True
		upd = True
		force = True

	elif o == ("-s"):
		sourceport = a

	elif o == ("--spider"):
		crawl = True

	elif o == ("-t"):
		try:
			if 6 > int(a) > 0:
				nmapspeed = a
			else:
				raise()
		except:
			print "%s\n  -= Scan Timing (-t) must be numeric and 1-5 =-\n" % msg
			sys.exit(1)

	elif o == ("--title"):
		if len(o) > 60:
			writelog("The title specified might not show up properly.", logfile)

		report_title = a

	elif o == ("--sslv"):
		sslopt = ",ssl-enum-ciphers"

	elif o in ("-q","--quiet"):
		quiet = True

	elif o == ("-r"):
		getrobots = True

	elif o == ("-y"): 
		import random;i="Random,Ragged,Rabid,Rare,Radical,Rational,Risky,Remote,Rowdy,Rough,Rampant,Ruthless:Act,Audit,Arming,Affront,Arc,Attack,Apex,Assault,Answer,Assembly,Attempt,Alerting,Arrest,Account,Apparel,Approval,Army:Wily,Weird,Wonky,Wild,Wascawy,Wimpy,Winged,Willing,Working,Warring,Wacky,Wasteful,Wealthy,Worried:Ravioli,Rats,Rabbits,Rhinos,Robots,Rigatoni,Reindeer,Roosters,Robins,Raptors,Raccoons,Reptiles".split(':'); e="%s %s of %s %s"%(random.choice(i[0].split(',')),random.choice(i[1].split(',')),random.choice(i[2].split(',')),random.choice(i[3].split(','))); e=(" "*((18-len(e)/2)))+e+(" "*((18-len(e)/2))); print banner.replace("  Rapid Assessment of Web Resources ",e[0:36]); sys.exit()

	elif o in ("-z","--compress-logs"):
		compress_logs = True

	else:
		print "\n  !! Unhandled option:  %s %s  !!\n" % (o, a)
		sys.exit(1)


# Remove the big dinosaur...  :\
if not quiet: 
	print banner


# Do some switch sanity checks
if len(sys.argv) < 2 or (len(sys.argv) < 3 and quiet):
	print usage
	sys.exit(1)
elif not (nmaprng != "" or nmap_il != "" or files or upd == True): 
	print "\n  !! No input specified / found in supplied path. !!\n"
	sys.exit(1)
elif (nmaprng != "" and nmap_il != ""):
	print "\n  !! Can't use -i and -n at the same time.  !!\n\n"
	sys.exit(1)


# Look for PhantomJS
if inpath("phantomjs"):
	pjs_path = "phantomjs"

elif os.path.exists("%s/data/phantomjs/bin/phantomjs" % scriptpath):
	pjs_path = "%s/data/phantomjs/bin/phantomjs" % scriptpath

elif system() in "CYGWIN|Windows" and inpath("phantomjs.exe"):
	pjs_path = "phantomjs.exe"

elif system() in "CYGWIN|Windows" and (os.path.exists("%s/data/phantomjs/phantomjs.exe" % scriptpath)):
	pjs_path = "%s/data//phantomjs/phantomjs.exe" % scriptpath

elif upd == False:
	print "  !! phantomJS not found in $PATH or in RAWR folder.  \n\n\tTry running 'rawr.py --check-install'\n\n  !! Exiting... !!\n\n"
	sys.exit(1)
else:
	pjs_path = ""


# Update if requested.
if upd == True:
	update(force, ckinstall, pjs_path, scriptpath)
	sys.exit(2)


# Create the log directory if it doesn't already exist.
if not os.path.exists(logdir): 
	os.makedirs(logdir)
	newdir = True

logfile = "%s/rawr_%s.log" % (logdir, timestamp)	
os.chdir(logdir)


# Check for the list of default passwords
if defpass:
	if os.path.exists("%s/%s" % (scriptpath, DEFPASS_FILE)): 
		writelog("\n   -= Located defpass.csv =-\n", logfile)
		# load defpass into memory - if it gets too big, this will change
		defpass = [line.strip() for line in open("%s/%s" % (scriptpath, DEFPASS_FILE))]
	else:
		writelog("\n   -= Unable to locate %s. =-\n" % DEFPASS_FILE, logfile)
		choice = raw_input("\tContinue without default password info? [Y|n] ").lower()
		defpass = False
		if (not choice in "yes") and choice != "": 
			print "\n   !! Exiting... !!\n\n"
			sys.exit(2)


# Build our global opener object
setdefaulttimeout(timeout)

if ver_dg:
	# downgrade to HTTP 1.0
	httplib.HTTPConnection._http_vsn = 10
	httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'

opener = urllib2.build_opener(urllib2.HTTPSHandler())
opener.addheaders = [('User-agent', useragent)]


msg = "\nStarted RAWR : %s\n     cmdline : %s\n\n" % (timestamp, " ".join(sys.argv))
open("%s/rawr_%s.log" % (logdir, timestamp),'a').write(msg)
writelog("\n  -= Log Folder created : %s =-\n" % logdir, logfile)


# Create a list called 'files', which contains filenames of all our .xml sources.
if nmap_il != "" or nmaprng != "":
	# Run NMap to provide discovery [xml] data
	if nmap_il != "" or (re.match('^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}(:[0-9]{1,5})?(\/.*)?$', nmaprng) or (re.match('^((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]{1}){1}){0,}|\*)\.(((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}){0,}|\*)\.){2}((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}){0,}|\*|([0]{1}\/(8|9|[1-2]{1}[0-9]{1}|30|31|32){1})){1}$', nmaprng) and not re.match('([-][0-9]{1,3}[-])|(([,-].*[/]|[/].*[,-])|([*].*[/]|[/].*[*]))', nmaprng) and not re.match('([-][0-9]{1,3}[-])|(([,-].*[/]|[/].*[,-])|([*].*[/]|[/].*[*]))', nmaprng))):
		# ^^ check for valid nmap input (can use hostnames, subnets (ex. 192.168.0.0/24), stars (ex. 192.168.*.*), and split ranges (ex. 192.168.1.1-10,14))
		if not (inpath("nmap") or inpath("nmap.exe")):
			writelog("  !! NMap not found in $PATH.  Exiting... !!\n\n", logfile)
			sys.exit(1)

		writelog("  -= Beginning NMap Scan =-", logfile)

		# Build the NMap command args
		cmd = ["nmap","-Pn"]

		if sourceport != "":
			cmd += "-g", sourceport

		cmd += "-p", ports ,"-T%s"%nmapspeed, "-vv", "-sV", "--script=ssl-cert"+sslopt, "-oA", "rawr_"+timestamp, "--open"

		if nmap_il != "": 
			cmd += "-iL", nmap_il
		else:
			cmd.append(nmaprng)

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


# Create the main queue and parse the files for hosts, placing them in the queue
q = Queue()
for filename in files:
	writelog("[>] Parsing\t: %s  for web hosts..." % filename, logfile)
	try:
		dom = minidom.parse(filename)

		if len(dom.getElementsByTagName('NexposeReport')) > 0:
			############
			# Nexpose
			############
			for node in dom.getElementsbyTagName('node'):
				ip = node.getElementsbyTagName('address').firstChild.nodeValue
				hostname = node.getElementsbyTagName('name').firstChild.nodeValue

				portnum = ""

				state = "open"

				protocol = ""

				owner = ""

				service = ""

				sunrpc_info = ""

				version_info = ""

				if web:
						q.put(", ".join([ip, hostname, portnum, state, protocol, owner, service, sunrpc_info, version_info]))

				elif allinfo:
					write_to_csv(timestamp, ip, hostname, portnum, state, protocol, owner, service, sunrpc_info, version_info)

		if len(dom.getElementsByTagName('ASSET_DATA_REPORT')) > 0:
			############
			# Qualys
			############
			for host in dom.getElementsByTagName('HOST'):
				hostname = ""
				ip = host.getElementsByTagName('IP')[0].firstChild.nodeValue
				if len(host.getElementsByTagName('DNS')) > 0:
					hostname = host.getElementsByTagName('DNS')[0].firstChild.nodeValue

				for name in host.getElementsByTagName('NETBIOS'):
							if not name.firstChild.nodeValue.lower() in hostname.lower():
								hostname += "|" + name.firstChild.nodeValue

				for vuln in host.getElementsByTagName('VULN_INFO'):
					if vuln.getElementsByTagName('QID')[0].firstChild.nodeValue in "86000;86001":
						for name in vuln.getElementsByTagName('FQDN'):
							if not name.firstChild.nodeValue.lower() in hostname.lower():
								hostname += "|" + name.firstChild.nodeValue

						portnum = vuln.getElementsByTagName('PORT')[0].firstChild.nodeValue
						state = "open"
						protocol = vuln.getElementsByTagName('PROTOCOL')[0].firstChild.nodeValue
						owner = ""
						service = vuln.getElementsByTagName('SERVICE')[0].firstChild.nodeValue
						sunrpc_info = ""
						version_info = vuln.getElementsByTagName('RESULT')[0].firstChild.nodeValue
						version_info = version_info.split("\t")[2]

						q.put(", ".join([ip, hostname, portnum, state, protocol, owner, service, sunrpc_info, version_info]))

		elif len(dom.getElementsByTagName('NessusClientData_v2')) > 0:
			############
			# Nessus
			############
			for node in dom.getElementsByTagName('ReportHost'): 
				for item in node.getElementsByTagName('ReportItem'):
					plugin = item.getAttribute('pluginName')
	 				if plugin == "Service Detection":
						hostname = node.getAttribute('name')
						service = item.getAttribute('svc_name')
						ip = ""
						state = ""
						owner = ""
						sunrpc_info = ""
						version_info = ""
						systype = ""

						for subele in node.getElementsByTagName('tag'):
							name = subele.getAttribute('name')
							val = subele.firstChild.nodeValue
							if name == "host-ip":
								ip = val
							elif name == "operating-system": 
								version_info = val
							elif name == "system-type": 
								systype = val
							elif name == "netbios-name": 
								hostname += ("|" + val)

						version_info += " (%s)"%systype
			
						protocol = item.getAttribute('protocol')
						portnum = item.getAttribute('port')
						plugin_output = item.getElementsByTagName("plugin_output")[0].firstChild.nodeValue
			
						service = "http"
						if any(s in plugin_output.lower() for s in ["ssl", "tls"]):
							service += "s"

						if (service == "www"):
							q.put(", ".join([ip, hostname, portnum, state, protocol, owner, service, sunrpc_info, version_info]))

						elif allinfo:
							write_to_csv(timestamp, ip, hostname, portnum, state, protocol, owner, service, sunrpc_info, version_info)

		elif len(dom.getElementsByTagName('nmaprun')) > 0:
			############
			# NMap
			############
			for node in dom.getElementsByTagName('host'): 
				if len(node.getElementsByTagName('ports')) > 0:
					for port in node.getElementsByTagName('ports')[0].getElementsByTagName('port'):
						if port.getElementsByTagName('state')[0].getAttribute('state') == "open": 
							ip = node.getElementsByTagName('address')[0].getAttribute('addr')
							hostname = []
							for hn in node.getElementsByTagName('hostname'):
								if not hn.getAttribute('name') in hostname:
									hostname.append(hn.getAttribute('name'))

							hostname = '|'.join(hostname)
							portnum = port.getAttribute('portid')
							protocol = port.getAttribute('protocol')
							state = port.getElementsByTagName('state')[0].getAttribute('state')
							owner = port.getElementsByTagName('owner')
							if len(owner) > 0: 
								owner = owner.getAttribute('name')
							else: 
								owner = " "

							# Enumerate service information
							service = "unknown"
							sunrpc_info = ""
							version_info = ""
							ele_service = port.getElementsByTagName('service')

							if len(ele_service) > 0: 
								ele_service = ele_service[0]
								service_tunnel = ele_service.getAttribute('tunnel')
								service = ele_service.getAttribute('name')
								if service_tunnel: 
									service = "%s|%s"%(ele_service.getAttribute('tunnel'),service)

								version_info = ele_service.getAttribute('product')
								if version_info != "": 
									version_info += " %s" % ele_service.getAttribute('version')

								ostype = ele_service.getAttribute('ostype')
								if ostype != "": 
									devtype = ele_service.getAttribute('devicetype')	
									if devtype != "": 
										version_info += " [%s - %s]" % (ostype, devtype)
									else: 
										version_info += " [%s]" % ostype

									xtra = ele_service.getAttribute('extrainfo')
									if xtra != "": 
										version_info += " (%s)" % xtra

							if any(s in service.lower() for s in ["ssl", "http", "tls"]):	
								q.put(", ".join([ip, hostname, portnum, state, protocol, owner, service, sunrpc_info, version_info]))	

							elif allinfo:
								write_to_csv(timestamp, ip, hostname, portnum, state, protocol, owner, service, sunrpc_info, version_info)

		else:
			writelog("    [!] Unrecognized file format.  [ %s ]" % filename, logfile)
			continue

	except Exception, ex:
		writelog("\n\n    [!] Unable to parse %s !\n\t\t Error: %s\n\n" % ( filename, ex ), logfile)

	writelog("    [>] Found [ %s ] web hosts in %s..." % ( q.qsize(), filename ), logfile)

	try:
		dom.unlink()
	except:
		pass

	dom = None


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
		if xmlfile == True:
			fname = os.path.basename(files[0])
		else:
			fname = "rawr_%s.xml" % timestamp

		filedat = open('index_%s.html' % timestamp).read()
		filedat = filedat.replace( '<!-- REPLACEWITHLINK -->', fname )
		filedat = filedat.replace( '<!-- REPLACEWITHDATE -->', datetime.now().strftime("%b %d, %Y") )
		filedat = filedat.replace( '<!-- REPLACEWITHTITLE -->', report_title )
		if nmap_il != "":
			report_range = nmap_il
			
		elif nmaprng != "":
			report_range = nmaprng
			
		else:
			if len(files) > 1:
				report_range = "%s files" % len(files)

			else:
				report_range = str(", ".join(files)[:40])

		
		filedat = filedat.replace( '<!-- REPLACEWITHRANGE -->', report_range )
		filedat = filedat.replace( '<!-- REPLACEWITHTIMESTAMP -->', timestamp )
		filedat = filedat.replace( '<!-- REPLACEWITHFLIST -->', flist )


		if logo_file != "":
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

	# Create the output queue - prevents output overlap
	output = Queue()
	o = out_thread(output, logfile)
	o.daemon = True
	o.start()

	# Create the main worker pool and get them started
	threads=[]
	for i in range(nthreads):
		t = sithread(q, opener, timestamp, scriptpath, pjs_path, logdir, output, bing_dns, getoptions, getrobots, defpass, crawl)
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

	if compress_logs:
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


