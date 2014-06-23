#!/usr/bin/env python

####
#
#	   RAWR - Rapid Assessment of Web Resources
#			   Written 2012 by Adam Byers  (@al14s)
#				   al14s@pdrcorps.com
#
#
#					  Romans 5:6-8
#
#	See the file 'docs/LICENSE' for copying permission.
#
####

import time
# start the stop-watch
start = time.time()

import optparse
from glob import glob

# Non stdlib - must be installed
from lxml import etree

from lib.banner import *
from conf.settings import *
from lib.functions import *

scriptpath = os.path.dirname(os.path.realpath(__file__))
unix_ts = datetime.now().strftime("%s")


def process_targets(targets):
	for target in targets:
		try:
			o1, o2, o3, o4 = target['ipv4'].split('.')
			target['ipnum'] = str((int(o1)*16777216) + (int(o2)*65536) + (int(o3)*256) + int(o4))

			# add this host/enum to the index
			if not target['ipnum'] in db['idx']:
				db['idx'][target['ipnum']] = {unix_ts: [target['port']]}

			else:
				if unix_ts in db['idx'][target['ipnum']]:
					if not target['port'] in db['idx'][target['ipnum']][unix_ts]:
						db['idx'][target['ipnum']][unix_ts].append(target['port'])

					else:
						continue

				else:
					db['idx'][target['ipnum']][unix_ts] = [target['port']]

			if opts.allinfo or 'http' in target['service_name']:
				if not target['ipv4'] in ints:
					try: x = target['hostnames'][0]
					except: x = target['ipv4']
					ints[target['ipv4']] = [x, [target['port']]]

				elif not target['port'] in ints[target['ipv4']][1]:
					ints[target['ipv4']][1].append(target['port'])

			if 'http' in target['service_name']:
				y = '.'.join([target['ipnum'], unix_ts, target['port']])
				if not y in db:
					db[y] = {}

				if not '.' in db[y]:
					db[y]['.'] = target
					q.put((y, '.'))

				for hn in target['hostnames']:
					if not hn in db[y] and not hn == target['ipv4']:
						db[y][hn] = target
						q.put((y, hn))

			if not opts.json_min:
				with open("%s/input_lists/%s_%s_iL.lst" % (logdir, target['port'], timestamp), 'a') as of:
					of.write(target['ipv4'] + '\n')

				with open("%s/input_lists/all_%s_iL.lst" % (logdir, timestamp), 'a') as of:
					of.write(target['ipv4'] + '\n')

		except Exception, ex:
			print ex

	db.sync()

	writelog("	  %s[+]%s Found [ %s ] web interface(s)\n" % (TC.CYAN, TC.END, len(targets)), logfile, opts)

print('\n')

# pull/parse our commandline args
parser = optparse.OptionParser(usage=usage, version=VERSION)
parser.add_option('-a',
				  help='Include all open ports in .csv, not just web interfaces. Creates a threat matrix as well.',
				  dest='allinfo', action='store_true', default=False)
parser.add_option('-f', metavar="<file>",
				  help='NMap|Metasploit|Nessus|Nexpose|Qualys|OpenVAS file or directory from which to pull files. '
				  'See README for valid formats. Use quotes when using wildcards. '
				  'ex:  -f "*.nessus" will parse all .nessus files in directory.', dest='xmlfile')
parser.add_option('-c', metavar="<rawr .cfg file>",
				  help='Use configuration file from previous scan.', dest='cfgfile')
parser.add_option('-i', metavar="<file>",
				  help="Supply a line-seperated input list. [NMap format] [can't be used with -n]", dest='nmap_il', default=False)
parser.add_option('-m', help="Process inputs, create an Attack Surface Matrix, and exit.",
				  dest='asm', action='store_true', default=False)
parser.add_option('-p', metavar="<port(s)>",
				  help="Specify port(s) to scan.   [default is '80,443,8080,8088']", dest='ports', default=ports)
parser.add_option('-s', metavar="<port>",
				  help='Specify a source port for the NMap scan.', dest='sourceport', type='int')
parser.add_option('-t', metavar="(1-5)",
				  help='Set a custom NMap scan timing.   [default is 4]', dest='nmapspeed', type='int', default=nmapspeed)
parser.add_option('-v', help='Verbose - Shows messages like spider status updates.',
				  dest='verbose', action='store_true', default=False)
parser.add_option('-y', help='', dest='y', action='store_true', default=False)
parser.add_option('--sslv', help='Assess the SSL security of each target.  [considered intrusive]', dest='sslopt',
				  action='store_true', default=False)

group = optparse.OptionGroup(parser, "DATABASE")
group.add_option('--db', metavar="<file>[n][,<file>[n]]",
				 help='Specify RAWR .db file from previous enumeration.' +
					  ' Will run enumeration with same settings as the specified scan, adding new data to the .db' +
					  ' and produce an HTML diff report.' +
					  ' Will accept two comma-seperated values as <file>[scan number], and compare the two. If no' +
					  ' scan number is specified, the latest one is used.', dest='compfile')
group.add_option('--db-list', metavar="<file>",
				 help='Lists all scans in a RAWR .db by their id, date, and options. Use this to determine which' +
					  " number to enter when using '-c'.", dest='qfile')
#parser.add_option_group(group)

group = optparse.OptionGroup(parser, "ENUMERATION")
group.add_option('-b', help='Use Bing to gather external hostnames. (good for shared hosting)', dest='bing_dns',
				 action='store_true', default=False)
group.add_option('-o', help="Make an 'OPTIONS' call to grab the site's available methods.", dest='getoptions',
				 action='store_true', default=False)
group.add_option('-r', help='Make an additional web call to get "robots.txt"', dest='getrobots', action='store_true',
				 default=False)
group.add_option('-x', help='Make an additional web call to get "crossdomain.xml"',
				 dest='getcrossdomain', action='store_true', default=False)
group.add_option('--downgrade', help='Make requests using HTTP 1.0', dest='ver_dg', action='store_true', default=False)
group.add_option('--noss', help='Disable screenshots.', dest='noss', action='store_true', default=False)
group.add_option('--proxy', metavar="<ip:port>",
				 help="<ip:port> Use Burp/Zap/W3aF to feed credentials to all sites.  " +
				 "** Recommended only for internal sites **", dest='proxy_dict')
group.add_option('--spider', help="Enumerate all urls in target's HTML, create site layout graph.  " +
				 "Will record but not follow links outside of the target's domain." +
				 "  Creates a map (.png) for that site in the <logfolder>/maps folder.",
				 dest='crawl', action='store_true', default=False)
group.add_option('-S', metavar="(1-5)", help="Use a pre-set crawl aggression level.  Levels are listed in settings.py.",
				 dest='crawl_level', type='int', default=False)
group.add_option('--spider-opts', metavar="<options>", help="Provide custom settings for crawl.			   " +
				 "s='follow subdomains',d=depth, l='url limit', t='crawl timeout', u='url timeout', th='thread limit'" +
				 "		Example: --spider-opts s:false,d:2,l:500,th:1",
				 dest='crawl_opts')
group.add_option('--alt-domains', metavar="<domains>",
				 help="Enable cross-domain spidering on specific domains. (comma-seperated)",
				 dest='alt_domains')
group.add_option('--blacklist-urls', metavar="<file>",
				 help="Blacklist specific urls during crawl. Requires a line-seperated input list.",
				 dest='spider_url_blacklist')
group.add_option('--mirror', help="Crawl and create a cached copy of sites, stored in the 'mirrored_sites' folder." +
				 "  Note: This will initiate a crawl, so --spider is not necessary.  Any regular spidering options" +
				 " can still be specified using the options above.",
				 dest='mirror', action='store_true', default=False)
parser.add_option_group(group)

group = optparse.OptionGroup(parser, "OUTPUT")
group.add_option('-d', metavar="<folder>",
				 help='Directory in which to create log folder [default is "./"]', dest='logdir')
group.add_option('-q', '--quiet', help="Won't show splash screen.", dest='quiet', action='store_true', default=False)
group.add_option('-z', help='Compress log folder when finished.',
				 dest='compress_logs', action='store_true', default=False)
group.add_option('--json', help='stdout will include only JSON strings. Log folders and files are created normally.',
				 dest='json', action='store_true', default=False)
group.add_option('--json-min', help='The only output of this script will be JSON strings to stdout.',
				 dest='json_min', action='store_true', default=False)
group.add_option('--parsertest', help='Will parse inputs, display the first 3, and exit.', dest='parsertest',
				 action='store_true', default=False)
parser.add_option_group(group)

group = optparse.OptionGroup(parser, "REPORTING")
group.add_option('-e', help='Exclude default username/password data from output.', dest='defpass', action='store_false',
				 default=True)
group.add_option('--logo', metavar="<file>", help='Specify a logo file for the HTML report.', dest='logo')
group.add_option('--title', metavar='"Title"', help='Specify a custom title for the HTML report.', dest='title', default=report_title)
parser.add_option_group(group)

group = optparse.OptionGroup(parser, "UPDATING")
group.add_option('-u', help='Check for newer version of required files.', dest='update',
				 action='store_true', default=False)
group.add_option('-U', help='Force update of required files.', dest='forceupdate', action='store_true',
				 default=False)
parser.add_option_group(group)

opts, args = parser.parse_args()

opts.nmaprng = False
if len(args) > 0:
	opts.nmaprng = args[0]

if opts.y:
	import random
	i = words.split(':')
	e = "%s %s of %s %s" % (random.choice(i[0].split(',')), random.choice(i[1].split(',')),
							random.choice(i[2].split(',')), random.choice(i[3].split(',')))
	e = (" "*((18-len(e)/2)))+e+(" "*((18-len(e)/2)))
	print(banner.replace("  Rapid Assessment of Web Resources ", e[0:36]))
	exit()


if opts.cfgfile:
	import ConfigParser

	config = ConfigParser.RawConfigParser()
	try: 
		config.read(opts.cfgfile)
	
	except Exception, ex:
		parser.error("  %s[x]%s Error opening %s:\n\t%s." % (TC.RED, TC.END, ex))
		sys.exit(1)

	#print dir(config), config.sections()
	print dir(opts)
	for i in config.items('Settings'):
		if i[1] in ('True', 'False'):
			x = bool(i[1])

		else:
			x = i[1]

		opts._update_loose( {i[0]: x} )

# Remove the big dinosaur...  :\
if not (opts.quiet or opts.json or opts.json_min):
	print(banner)


# sanity check
if sum(map(bool, [opts.nmap_il, opts.nmaprng, opts.xmlfile, opts.compfile])) > 1:
	parser.error("  %s[x]%s Can't use --url, -c, -f, -i, or -n in the same command." % (TC.RED, TC.END))
	sys.exit(1)

elif sum(map(bool, [opts.crawl_level, opts.crawl_opts])) > 1:
	parser.error("  %s[x]%s Can't use -S and --spider-opts in the same command." % (TC.RED, TC.END))
	sys.exit(1)

# Look for PhantomJS
pjs_path = False
if inpath("phantomjs"):  # installed elsewhere on the system
	pjs_path = "phantomjs"

elif os.path.exists("%s/data/phantomjs/bin/phantomjs" % scriptpath):  # the rawr/data folder
	pjs_path = "%s/data/phantomjs/bin/phantomjs" % scriptpath

elif platform_type in "CYGWIN|Windows" and inpath("phantomjs.exe"):  # Windows, installed elsewhereon system
	pjs_path = "phantomjs.exe"

elif platform_type in "CYGWIN|Windows" and (os.path.exists("%s/data/phantomjs/phantomjs.exe" % scriptpath)):
	pjs_path = "%s/data//phantomjs/phantomjs.exe" % scriptpath
	

if opts.update:
	update(pjs_path, scriptpath, False)

elif opts.forceupdate:
	update(pjs_path, scriptpath, True)


if not pjs_path:
	print("  %s[x]%s phantomJS not found in $PATH or in RAWR folder.  \n\n\tTry running 'rawr.py -u'\n\n\tOr"
	  " run rawr without screenshots (--noss)\n\n  %s[x]%s Exiting... !!\n\n" % (TC.RED, TC.END, TC.RED, TC.END))
	sys.exit(1)


# Take a look at our inputs
if False or opts.compfile:  # disabled for now
	# check if actual RAWR db output
	if not True:
		parser.error("  %s[x]%s -c <file> must be a RAWR db file." % (TC.RED, TC.END))
		sys.exit(1)

elif opts.nmaprng and 'http' in opts.nmaprng:  # accept a single url and use it to build out our target
	parsed_url = urlparse(opts.nmaprng)

elif opts.xmlfile:  # need to test this is a bunch of different cases
	ftemp = []
	if "*" in opts.xmlfile or os.path.isdir(opts.xmlfile):
		if os.path.isdir(opts.xmlfile):
			opts.xmlfile += "/*"
		
		for f in glob_recurse(opts.xmlfile):
			try:  # quick way to weed out extention-less files
				if os.path.splitext(f)[1] in ('.xml', '.csv', '.nessus'):
					ftemp.append(f)
					
			except:
				pass

	elif "," in opts.xmlfile:  # CSV list of files
		ftemp = opts.xmlfile.split(',')

	else:
		ftemp.append(opts.xmlfile)

	files = []
	for f in ftemp:
		if not os.path.isfile(os.path.abspath(f)):  # path not found
			print("\n\n\n  %s[x]%s Unable to locate: \n\t%s\n" % (TC.RED, TC.END, os.path.abspath(f)))

		else:
			files.append(os.path.abspath(f))

	if len(files) < 1:
		print("\n  %s[x]%s  No usable files specified. \n" % (TC.RED, TC.END))
		sys.exit(1)

elif opts.nmap_il or opts.nmaprng:
	if opts.nmap_il:
		if os.path.isfile(opts.nmap_il):
			opts.nmap_il = os.path.realpath(opts.nmap_il)

		else:
			print("  %s[x]%s Unable to locate file \n  [%s]. =-\n" % (TC.RED, TC.END, opts.nmap_il) )
			sys.exit(1)

	if opts.ports:
		if str(opts.ports).lower() == "fuzzdb":
			opts.ports = fuzzdb

		elif str(opts.ports).lower() == "all":
			opts.ports = "1-65535"

		else:
			opts.ports = str(opts.ports)

	if opts.nmapspeed:
		try:
			if not (6 > int(opts.nmapspeed) > 0): raise()

		except:
			print("\n  %s[x]%s  Scan Timing (-t) must be numeric and 1-5 \n" % (TC.RED, TC.END))
			sys.exit(1)

else:
	print("%s\n  %s[x]%s  No input specified. \n" % (usage, TC.RED, TC.END))
	sys.exit(1)


if opts.logdir:
	# redefine logdir based on user request
	logdir = os.path.realpath(opts.logdir) + "/log_%s_rawr" % timestamp

#elif platform_type == "armv7":
#	logdir = "?"

else:
	logdir = os.path.realpath("log_%s_rawr" % timestamp)

logfile = "%s/rawr_%s.log" % (logdir, timestamp)

newdir = False
if not opts.json_min:  # Create the log directory if it doesn't already exist.
	if not os.path.exists(logdir): 
		os.makedirs(logdir)
		newdir = True

	os.chdir(logdir)

	import ConfigParser
	config = ConfigParser.RawConfigParser()
	config.add_section('Settings')
	x = eval(str(parser.values))
	y = eval(str(parser.get_default_values()))
	if 'nmaprng' in x:
		config.set('Settings', 'nmaprng', x['nmaprng'])
		del x['nmaprng']

	for opt in x.keys():
		if not x[opt] == y[opt]:
			config.set('Settings', opt, x[opt])

	with open('rawr_%s.cfg' % timestamp, 'wb') as configfile:
		config.write(configfile)

if opts.crawl or opts.mirror:
	if opts.crawl_level:
		sl = opts.crawl_level
	
	else:
		sl = 3  # default
	
	#  Populate the default options
	opts.spider_follow_subdomains, opts.spider_depth, \
	opts.spider_timeout, opts.spider_url_timeout, \
	opts.spider_url_limit, opts.spider_thread_limit, \
	opts.spider_breadth_first, opts.spider_url_max_hits = spider_levels[sl]

	try:
		if opts.crawl_opts:
			for o in opts.crawl_opts.split(','):
				a, v = o.split(':')
				if a == "s":
					if v.lower() in ("false", "f"):
						opts.spider_follow_subdomains = False
						writelog("\n  %s[i]%s spider_follow_subdomains set to 'False'" % (TC.BLUE, TC.END), logfile, opts)

					elif v.lower() in ("true", "t"):
						opts.spider_follow_subdomains = True
						writelog("\n  %s[i]%s spider_follow_subdomains set to 'True'" % (TC.BLUE, TC.END), logfile, opts)

				elif a == "d" and int(v) in range(0, 999):
					opts.spider_depth = int(v)
					writelog("\n  %s[i]%s spider_depth set to '%s'" % (TC.BLUE, TC.END, v), logfile, opts)

				elif a == "t" and int(v) in range(0, 999):
					opts.spider_timeout = int(v)
					writelog("\n  %s[i]%s spider_timeout set to '%s'" % (TC.BLUE, TC.END, v), logfile, opts)

				elif a == "th" and int(v) in range(0, 999):
					opts.spider_thread_limit = int(v)
					writelog("\n  %s[i]%s spider_thread_limit set to '%s'" % (TC.BLUE, TC.END, v), logfile, opts)

				elif a == "l" and int(v) in range(0, 9999):
					opts.spider_url_limit = int(v)
					writelog("\n  %s[i]%s spider_url_limit set to '%s'" % (TC.BLUE, TC.END, v), logfile, opts)

				elif a == "u" and int(v) in range(0, 9999):
					opts.spider_url_timeout = int(v)
					writelog("\n  %s[i]%s spider_url_timeout set to '%s'" % (TC.BLUE, TC.END, v), logfile, opts)

				# elif a == "h" and int(v) in range(0, 999):
				#		opts.spider_url_max_hits = int(v)
				#		writelog("\n  %s[i]%s spider_url_max_hits set to '%s'" % (TC.BLUE, TC.END, v), logfile, opts)

	except Exception:
		print("	  %s[!]%s Error with --spider_opts:  '%s'\n\n\t\t%s" % (TC.YELLOW, TC.END, opts.crawl_opts, traceback.format_exc().replace('\n', '\n\t\t')))
		exit()

if opts.logo:
	if os.path.exists(os.path.abspath(opts.logo)):
		try:
			l, h = Image.open(os.path.abspath(opts.logo)).size
			if l > 400 or h > 80:
				writelog("  %s[!]%s  The specified logo may not show up correctly.\n\tA size no larger than 400x80 is "
						 "recommended.\n" % (TC.YELLOW, TC.END), logfile, opts)

		except:
			pass

		logo_file = os.path.realpath(opts.logo)

	else:
		print("\t  %s[x]%s  Unable to locate logo file \n\t\t[%s] \n" % (TC.RED, TC.END, opts.logo))
		sys.exit(1)

if opts.title and len(opts.title) > 60:
	writelog("  %s[!]%s warning - The title specified is longer than 60 characters and might not show up properly." % (TC.YELLOW, TC.END), logfile, opts)


# Check for the list of default passwords
if opts.defpass:
	if os.path.exists("%s/%s" % (scriptpath, DEFPASS_FILE)):
		writelog("\n  %s[i]%s Located defpass.csv\n" % (TC.BLUE, TC.END), logfile, opts)

	else:
		writelog("  %s[!]%s Unable to locate %s. =-\n" % (TC.BLUE, TC.END, DEFPASS_FILE), logfile, opts)
		choice = raw_input("\tContinue without default password info? [Y|n] ").lower()
		defpass = False
		if (not choice in "yes") and choice != "":
			print("\n  %s[x]%s Exiting... \n\n" % (TC.RED, TC.END))
			sys.exit(2)

# Check for the IpToCountry list
if os.path.exists("%s/%s" % (scriptpath, IP_TO_COUNTRY)):
	writelog("\n  %s[i]%s Located IpToCountry.csv\n" % (TC.BLUE, TC.END), logfile, opts)

else:
	writelog("  %s[!]%s Unable to locate %s. =-\n" % (TC.YELLOW, TC.END, IP_TO_COUNTRY), logfile, opts)
	choice = raw_input("\tContinue without Ip to Country info? [Y|n] ").lower()
	defpass = False
	if (not choice in "yes") and choice != "":
		print("\n  %s[x]%s Exiting... \n\n" % (TC.RED, TC.END))
		sys.exit(2)

if not opts.json_min:
	msg = "\nStarted RAWR : %s\n	 cmdline : %s\n\n" % (timestamp, " ".join(sys.argv))
	open("%s/rawr_%s.log" % (logdir, timestamp), 'a').write(msg)  # Log created
	writelog("\n  %s[+]%s Log Folder created:\n	  %s \n" % (TC.CYAN, TC.END, logdir), logfile, opts)  # Second log entry


if opts.ver_dg:
	writelog("  %s[i]%s Downgrading all requests to HTTP/1.0...\n" % (TC.BLUE, TC.END), logfile, opts)
	import httplib  # requests uses urllib3, which uses httplib...
	httplib.HTTPConnection._http_vsn = 10
	httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'

if opts.proxy_dict:
	opts.proxy_dict = {"http": opts.proxy_dict, "https": opts.proxy_dict}

delthis = False

# Create a list called 'files', which contains filenames of all our .xml sources.
if opts.nmap_il or opts.nmaprng and not 'http' in opts.nmaprng:
	files = []
	# Run NMap to provide discovery [xml] data
	if opts.nmap_il != "" \
		or (re.match('^[a-z0-9]+([\-\.][a-z0-9]+)*\.[a-z]{2,6}(:[0-9]{1,5})?(/.*)?$', opts.nmaprng)
			or (re.match(NMAP_INPUT_REGEX, opts.nmaprng)
			and not re.match('([-][0-9]{1,3}[-])|(([,-].*[/]|[/].*[,-])|([*].*[/]|[/].*[*]))', opts.nmaprng))):
		# ^^ check for valid nmap input (can use hostnames, subnets (ex. 192.168.0.0/24), stars (ex. 192.168.*.*),
		# and split ranges (ex. 192.168.1.1-10,14))
		if not (inpath("nmap") or inpath("nmap.exe")):
			writelog("  %s[x]%s NMap not found in $PATH.  Exiting... \n\n" % (TC.RED, TC.END), logfile, opts)
			sys.exit(1)

		# Build the NMap command args
		cmd = ["nmap", "-Pn"]

		if opts.sourceport:
			cmd += "-g", str(opts.sourceport)

		sslscripts = "--script=ssl-cert"
		if opts.sslopt:
			sslscripts += ",ssl-enum-ciphers"

		if opts.json_min:
			outputs = "-oX"
			fname = "rawr_" + timestamp + ".xml"

		else:
			outputs = "-oA"
			fname = "rawr_" + timestamp

		proc = subprocess.Popen(['nmap', '-V'], stdout=subprocess.PIPE)
		ver = proc.stdout.read().split(' ')[2]

		# greatly increases scan speed, introduced in nmap v.6.4
		if float(ver) > 6.3:
			cmd += "--max-retries", "0"

		cmd += "-p", opts.ports, "-T%s" % opts.nmapspeed, "-vv", "-sV", sslscripts, outputs, fname, "--open"

		if opts.nmap_il:
			cmd += "-iL", opts.nmap_il

		else:
			cmd.append(opts.nmaprng)

		writelog("  %s[>]%s Scanning >\n	  %s" % (TC.GREEN, TC.END, " ".join(cmd)), logfile, opts)

		# need to quiet this when running with --json & --json-min
		try:
			if not (opts.json_min or opts.json):
				with open("%s/rawr_%s.log" % (logdir, timestamp), 'ab') as log_pipe:
					ret = subprocess.call(cmd, stderr=log_pipe)

			else:
				with open('/dev/null', 'w') as log_pipe:
					ret = subprocess.Popen(cmd, stdout=log_pipe, stderr=subprocess.PIPE).wait()

		except KeyboardInterrupt:
			writelog("\n\n  %s[!]%s  Scanning Halted (ctrl+C).  Exiting!   \n\n" % (TC.YELLOW, TC.END), logfile, opts)
			sys.exit(2)

		except Exception:
			error = traceback.format_exc().replace('\n', '\n\t\t')
			error_msg(error)
			writelog("\n\n  %s[x]%s  Error in scan - %s\n\n" % (TC.RED, TC.END, error), logfile, opts)
			sys.exit(2)

		if ret != 0:
			writelog("\n\n", logfile, opts)
			sys.exit(1)

		files = ["rawr_%s.xml" % timestamp]

	else:
		writelog("\n  %s[!]%s Specified address range is invalid. !!\n" % (TC.YELLOW, TC.END), logfile, opts)
		sys.exit(1)

elif newdir and (not opts.nmaprng or not 'http' in opts.nmaprng): # Move the user-specified xml file(s) into the new log directory
	for fname in files:
		shutil.copyfile(fname, "./"+os.path.basename(fname))

if not opts.json_min: # Look for and copy any images from previous scans
	if not newdir and not (glob("*.png") or glob("images/*.png")):
		writelog("\n  %s[!]%s No thumbnails found in [%s/]\n	  or in [.%s/images/]. **\n" %
				 (TC.YELLOW, TC.END, os.getcwd(), os.getcwd()), logfile, opts)
		if not opts.noss:
			writelog("	  Will take website screenshots during the enumeration. ", logfile, opts)

	else:
		png_files = glob("*.png")
		if not os.path.exists("images") and (not opts.noss or len(png_files) > 0):
			os.mkdir("images")

		for filename in glob("*.png"):
			newname = filename.replace(":", "_")
			os.rename(filename, "./images/%s" % newname)

	os.makedirs('%s/input_lists' % logdir)

db = shelve.open('rawr_%s' % timestamp, writeback=True) # need to figure out if this is going to be writeback or not
db['idx'] = {}
ints = {}

if opts.nmaprng and 'http' in opts.nmaprng:
	targets = []
	target = {}
	host = parsed_url.netloc.split(':')[0]

	if re.search("0-9.+", host):
		target['ipv4'] = host
		target['hostnames'] = [socket.gethostbyaddr(host)]

	else:
		target['hostnames'] = [host]
		target['ipv4'] = socket.gethostbyname(host)

	target['service_name'] = parsed_url.scheme
	
	if ':' in parsed_url.netloc:
		target['port'] = parsed_url.netloc.split(':')[1]

	elif parsed_url.scheme == "https":
		target['port'] = '443'
		target['service_tunnel'] = 'ssl'

	else:
		target['port'] = '80'

	target['url'] = opts.nmaprng

	process_targets([target])

else:
	for filename in files:
		writelog("\n  %s[>]%s Parsing: %s" % (TC.GREEN, TC.END, filename), logfile, opts)
		try:
			if filename.endswith(".csv"):
				with open(filename) as r:
					head = ' '.join([r.next() for x in xrange(2)])

				if 'Asset Group:' in head:
					targets = parse_qualys_port_service_csv(filename)

				else:  # generic CSV
					targets = parse_csv(filename)

			elif filename.endswith(".nessus"):
				r = etree.parse(filename)

				if len(r.xpath('//NessusClientData_v2')) > 0:
					targets = parse_nessus_xml(r)

				else:
					writelog("	  %s[!]%s Unrecognized file format.\n\n" % (TC.YELLOW, TC.END), logfile, opts)
					continue

			elif filename.endswith(".xml"):
				r = etree.parse(filename)

				if len(r.xpath('//NexposeReport')) > 0:
					targets = parse_nexpose_xml(r)

				elif len(r.xpath('//NeXposeSimpleXML')) > 0:
					targets = parse_nexpose_simple_xml(r)

				elif len(r.xpath('//ASSET_DATA_REPORT')) > 0:
					targets = parse_qualys_scan_report_xml(r)

				elif len(r.xpath('//nmaprun')) > 0:
					targets = parse_nmap_xml(r)

				elif len(r.xpath('//report[@extension="xml" and @type="scan"]')) > 99:
					targets = parse_openvas_xml(r)

				else:
					writelog("	  %s[!]%s Unrecognized file format.\n\n" % (TC.YELLOW, TC.END), logfile, opts)
					continue

			else:
				writelog("	  %s[!]%s Unsupported file type.\n\n" % (TC.YELLOW, TC.END), logfile, opts)
				continue

		except Exception:
			error = traceback.format_exc().replace('\n', '\n\t\t')
			error_msg(error)
			writelog("	  %s[!]%s Unable to parse: \n\t\t Error: %s\n\n" % (TC.YELLOW, TC.END, error), logfile, opts)
			continue

		process_targets(targets)


# cleaning up for the --json-min run
if opts.json_min:
	os.remove(files[0])

if q.qsize() > 0:
	if not opts.json_min:
		writelog("\n  %s[>]%s Building Attack surface matrix" % (TC.GREEN, TC.END), logfile, opts)

		# create the attack surface matrix
		asm_f = "%s/rawr_%s_attack_surface.csv" % (logdir, timestamp)
		try:
			ports = []
			for i in ints:
				for p in ints[i][1]:
					if not p in ports:
						ports.append(p)

			ports.sort(key=int)	# ports is a list of ports found while parsing files
			cols = ["IP", "HOSTNAME"] + ports + [" ", "TOTAL"]

			with open(asm_f, 'a') as f:
				f.write('"' + '","'.join(cols) + '"\n')  # write the column headers

				for ip in ints:  # ints is a list of interfaces found while parsing files
					hn, ports = ints[ip]
					line = [ip, hn] + [" "] * (len(cols)-3)
					for port in ports:
						line[cols.index(port)] = "x"

					line += (str(line.count("x")))
					f.write('"' + '","'.join(line) + '"\n')

				line = ["TOTAL"] + [" "] * len(cols)
				for port in ports:
					line[cols.index(port)] = str(ports.count(port))  # fill out the last line w/ count totals

				f.write('\n"' + '","'.join(line) + '"\n')

		except:
			error = traceback.format_exc()
			error_msg(error)
			writelog("\n  %s[!]%s Error creating attack surface matrix :\n\t%s\n" %
					 (TC.YELLOW, TC.END, error), logfile, opts)

		if opts.asm:  # quit after creating the asm
			print('\n\n')
			db.close()
			exit(0)

	# Begin processing any hosts found
	if not opts.json_min:
		# Create the folder for html resource files
		if not os.path.exists("./html_res"):
			os.makedirs("./html_res")

		shutil.copy("%s/data/jquery.js" % scriptpath, "./html_res/jquery.js")
		shutil.copy("%s/data/style.css" % scriptpath, "./html_res/style.css")
		shutil.copy("%s/data/report_template.html" % scriptpath, 'index_%s.html' % timestamp)

		# Make the link to NMap XML in our HTML report
		if opts.xmlfile:
			fname = os.path.basename(files[0])

		else:
			fname = "rawr_%s.xml" % timestamp

		report_range = ""
		if opts.nmap_il:
			report_range = os.path.basename(str(opts.nmap_il))

		elif opts.nmaprng:
			report_range = str(opts.nmaprng)

		else:
			try:
				if type(files) == list:
					if len(files) == 1:
						report_range = os.path.basename(files[0])

					else:
						report_range = "%s files" % len(files)

				else:
					report_range = os.path.basename(str(files))

			except:
				report_range = opts.nmaprng

		with open('sec_headers_%s.html' % timestamp, 'a') as of:
			of.write("""<html>\n<head>\n<title>Security Headers Report</title>\n<style>\n""" + \
					 """table,th,td{border-spacing: 0px;border: 1px solid black; text-align:center; font-size:85%; letter-spacing:1px;}\n""" + \
					 """th{font-size:12px;font-weight:bold;background-color:f2f2f2;}\n""" + \
					 """p{font-size:85%; margin: 5; padding: 0;}\n""" + \
					 """h5{margin: 0; padding: -5;}\n""" + \
					 """h6{margin: 0; padding: 0;}\n""" + \
					 """</style></head>\n<body>\n<table>\n<tr><th style='background-color:""" + \
					 """ffffff;'></th><th>access-control-allow-origin</th><th>content-""" + \
					 """security-policy</th><th>server</th><th>strict-transport-security""" + \
					 """</th><th>x-content-type-options</th><th>x-frame-options</th><th>""" + \
					 """x-permitted-cross-domain-policies</th><th>x-powered-by</th><th>""" + \
					 """x-xss-protection</th></tr>""")

		filedat = open('index_%s.html' % timestamp).read()
		if os.path.exists(fname):
			x = '<li><a class="textwds" onselect=False target="_blank" href="%s">NMap XML</a></li>' % fname
			filedat = filedat.replace('<!-- REPLACEWITHLINK -->', x)

		filedat = filedat.replace('<!-- REPLACEWITHDATE -->', datetime.now().strftime("%b %d, %Y"))
		filedat = filedat.replace('<!-- REPLACEWITHTITLE -->', opts.title)
		filedat = filedat.replace('<!-- REPLACEWITHRANGE -->', report_range)
		filedat = filedat.replace('<!-- REPLACEWITHTIMESTAMP -->', timestamp)
		filedat = filedat.replace('<!-- REPLACEWITHSECHEADERS -->', "sec_headers_%s.html" % timestamp)
		filedat = filedat.replace('<!-- REPLACEWITHFLIST -->', ("hist, " + flist.replace('hist, ', '')))

		if opts.logo:
			shutil.copy(logo_file, "./html_res/")
			l = ('\n<img id="logo" height="80px" src="./html_res/%s" />\n' % os.path.basename(logo_file))
			filedat = filedat.replace('<!-- REPLACEWITHLOGO -->', l)

		open('index_%s.html' % timestamp, 'w').write(filedat)

		if os.path.exists("%s/data/nmap.xsl" % scriptpath):
			if not os.path.exists("./html_res/nmap.xsl"):
				shutil.copy("%s/data/nmap.xsl" % scriptpath, "./html_res/nmap.xsl")

			for xmlfile in glob("rawr_*.xml"):
				fileloc = re.findall(r'.*href="(.*)" type=.*', open(xmlfile).read())[0]
				filedat = open(xmlfile).read().replace(fileloc, 'html_res/nmap.xsl')
				open(xmlfile, 'w').write(filedat)

			writelog("\n  %s[i]%s Copied nmap.xsl to %s\n\tand updated link in files.\n" % (TC.BLUE, TC.END, logdir), logfile, opts)

		else:
			writelog("\n  %s[!]%s Unable to locate nmap.xsl.\n" % (TC.YELLOW, TC.END), logfile, opts)

		if not os.path.exists("rawr_%s_serverinfo.csv" % timestamp):
			open("rawr_%s_serverinfo.csv" % timestamp, 'w').write('"' + flist.replace(', ', '","') + '"')

		writelog("\n  %s[>]%s Beginning enumeration of [ %s ] target[s].\n" % (TC.GREEN, TC.END, q.qsize()), logfile, opts)

	# Create the output queue - prevents output overlap
	o = OutThread(output, logfile, opts)
	o.daemon = True
	o.start()

	# Create the main worker pool and get them started
	for i in range(nthreads):
		t = SiThread(db, timestamp, scriptpath, pjs_path, logdir, output, opts)
		threads.append(t)
		t.daemon = True
		t.start()

	try:
		q.join()

		# Queue is clear, tell the threads to close.
		output.put("\n\n  %s[i]%s   ** Finished.  Stopping Threads. **\n" % (TC.BLUE, TC.END))

	except KeyboardInterrupt:
		print("\n\n  %s[i]%s  ******  Ctrl+C recieved - All threads halted.  ****** \n\n" % (TC.BLUE, TC.END))

	finally:
		for t in threads:
			t.terminate = True

	# Close our output queue and clear our main objects
	output.join()
	output = None
	t = None
	o = None
	q = None

	# Add the data and ending tags to the HTML report
	if not opts.json_min:
		with open('index_%s.html' % timestamp, 'a') as of:
			of.write("</div></body></html>")

		with open('sec_headers_%s.html' % timestamp, 'a') as of:
			of.write("""</table><br><br>\n<h5>Access Control Allow Origin (Access-Control-""" + \
					 """Allow-Origin)</h5>\n<p>\nModern websites often include content dyn""" + \
					 """amically pulled in from other sources online. SoundCloud, Flickr, """ + \
					 """Youtube and many other important websites use a technique called """ + \
					 """Cross Object Resource Sharing (CORS) to do so. Access Control Allow""" + \
					 """ Origin is a header that is part of the "conversation" between the """ + \
					 """site a that wants to include data from another site.\n</p>\n<h5>Content""" + \
					 """ Security Policy (Content-Security-Policy)</h5>\n<p>Content Security """ + \
					 """Policy (CSP) prevents cross site scripting by explicitly declaring to """ + \
					 """browsers which script, media, stylesheets, etc are supposed to be run""" + \
					 """ from your website. By whitelisting these resources, if an attacker is""" + \
					 """ ever able to embed his evil code on your site, the browser will ignore""" + \
					 """ it and visitors to your site will remain safe.\n</p>\n<h5>Cross Domain""" + \
					 """ Meta Policy (X-Permitted-Cross-Domain-Policies)</h5>\n<p>This header""" + \
					 """ tells Flash and PDF files which Cross Domain Policy files found on""" + \
					 """ your site can be obeyed; yes, it's a policy about other policies!""" + \
					 """</p>\n</p>\n<h5>Content Type Options (X-Content-Type-Options)</h5>""" + \
					 """\n<p>Microsoft Internet Explorer (IE) and Google Chrome have the """ + \
					 """ability to guess the type of content may be found in a file, a """ + \
					 """process called "MIME-sniffing". Since the browser can be tricked """ + \
					 """by an attacker into making the incorrect decision about types of """ + \
					 """files it sees online, webmasters can tell IE/Chrome to not to sniff.""" + \
					 """ That directive is called "nosniff" and it's communicated to via HTTP""" + \
					 """ headers.</p>\n</p>\n<h5>Server Information (Server)</h5>\n<p>The """ + \
					 """principle of least privilege says you only get access to stuff you """ + \
					 """need access to. Often times there is no reason for a server to advertise""" + \
					 """ its information via headers.  Removing the server header won't stop """ + \
					 """attacks but can make them slightly more difficult.</p>\n</p>\n<h5>Strict""" + \
					 """ Transport Security (Strict-Transport-Security)</h5>\n<p>Using the HSTS""" + \
					 """ header tells browsers that they should first make requests to your site""" + \
					 """ over HTTPS by default!</p>\n</p>\n<h5>Frame Options (X-Frame-Options)""" + \
					 """</h5>\n<p>The X Frame Options header is designed to minimize the """ + \
					 """likelihood that an attacker can use a clickjacking attack against your""" + \
					 """ site. In a clickjacking attack, the bad guy places a frame that """ + \
					 """invisibly renders your site over top of some other content below """ + \
					 """that is tempting for users to click on. </p>\n</p>\n<h5>Powered """ + \
					 """By Information (X-Powered-By)</h5>\n<p>The principle of least """ + \
					 """privilege says you only get access to stuff you need access to. """ + \
					 """Often times there is no reason to advertise your software version""" + \
					 """ information via headers.  Removing the x-powered-by header won't """ + \
					 """stop attacks but can make them slightly more difficult.</p>\n</p>\n""" + \
					 """<h5>XSS Protection (X-XSS-Protection)</h5>\n<p>Tells browsers such """ + \
					 """as IE and Chrome to be even more strict when they suspect an xss """ + \
					 """attack.  The header can designate the browser to not render the page,""" + \
					 """ try to remove/encode dangerous characters, or provide no additional""" + \
					 """ protection.</p>\n<h6>Descriptions provided by""" + \
					 """ <a href="https://securityheaders.com">https://securityheaders.com</a>""" + \
					 """</h6></body></html>""")

		# Sort the csv on the specified column
		try:
			i = flist.lower().split(", ").index(csv_sort_col)
			data_list = [l.strip() for l in open("rawr_%s_serverinfo.csv" % timestamp)]
			headers = data_list[0]
			data_list = data_list[1:]
			# Format IP adresses so we can sort them effectively
			if re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}" +
						"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", l.split(",")[i]):
				key = "%3s%3s%3s%3s" % tuple(l.split(",")[i].split('.'))

			else:
				key = l.split(",")[i]

			data_list.sort(key=lambda d: key)
			open("rawr_%s_serverinfo.csv" % timestamp, 'w').write("%s\n%s" % (headers, "\n".join(data_list)))

		except:
			writelog("\n  %s[!]%s '%s' was not found in the column list.  Skipping the CSV sort function." %
					 (TC.YELLOW, TC.END, csv_sort_col), logfile, opts)

		writelog("\n  %s[+]%s Report created in [%s/]\n" % (TC.CYAN, TC.END, os.getcwd()), logfile, opts)

		if opts.compress_logs:
			writelog("  %s[>]%s Compressing logfile...\n" % (TC.GREEN, TC.END), logfile, opts)
			logdir = os.path.basename(os.getcwd())
			os.chdir("../")
			try:
				if system() in "CYGWIN|Windows":
					shutil.make_archive(logdir, "zip", logdir)
					logdir_c = logdir + ".zip"
				else:
					tfile = tarfile.open(logdir + ".tar", "w:gz")
					tfile.add(logdir)
					tfile.close()
					logdir_c = logdir + ".tar"

				writelog("  %s[+]%s Created  %s ++\n" % (TC.CYAN, TC.END, logdir_c), logfile, opts)
				if os.path.exists(logdir) and os.path.exists(logdir_c):
					shutil.rmtree(logdir)

			except Exception:
				error = traceback.format_exc().replace('\n', '\n\t\t')
				error_msg(error)
				writelog("  %s[!]%s Failed\n\t%s\n" % (TC.YELLOW, TC.END, error), logfile, opts)

else:
	writelog("\n  %s[!]%s No data returned. \n\n" % (TC.YELLOW, TC.END), logfile, opts)

try: db.close()
except: pass

if not (opts.json or opts.json_min):
	elapsed = time.time() - start
	print "Time taken: ", elapsed, "seconds."

elif opts.json_min:
	try: os.remove('rawr_%s' % timestamp)
	except:
		try: os.remove('rawr_%s.db' % timestamp)
		except: pass

