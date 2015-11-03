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

import time
import argparse
import os
import sys
import getpass
from glob import glob
from lxml import etree
from lib.banner import *
from conf.settings import *

# Local Imports
from lib.functions import *

# pull/parse our commandline args
from argparse import RawTextHelpFormatter
# start the stop-watch
start = time.time()
scriptpath = os.path.dirname(os.path.realpath(__file__))

parser = argparse.ArgumentParser(argument_default=False, usage=usage, epilog='  \n\n',
                                 formatter_class=RawTextHelpFormatter)
if len(sys.argv) > 1:
    if not any(x for x in ("-U", "-u", "-y") if x in sys.argv):
        parser.add_argument('target_input',
                            help='URL, NMap range, RAWR .cfg file, NMap Input List,\n NMap|Metasploit|Nessus|' +
                                 'Nexpose|Qualys|OpenVAS XML\n report, or directory from which to pull these' +
                                 ' files.\n  See README for valid formats. Use quotes when using\n wildcards.\n' +
                                 '  ex:  "*.nessus" will parse all .nessus files\n   in directory (GLOB).')

parser.add_argument('-a', help='Include all open ports in .csv and surface matrix.', dest='allinfo',
                    action='store_true')
parser.add_argument('-m', help="Process inputs, create an Attack Surface Matrix,\n   then exit.", dest='asm',
                    action='store_true')
parser.add_argument('-p', metavar="<port(s)>", help="Specify port(s) to scan.\n   [default is '80,443,8080,8088']",
                    dest='ports', default='')
parser.add_argument('-s', metavar="<port>", help='Specify a source port for the NMap scan.', dest='sourceport',
                    type=int)
parser.add_argument('-t', metavar="(1-5)", help='Set a custom NMap scan timing.   [default is 4]', dest='nmapspeed',
                    type=int, default=nmapspeed)
parser.add_argument('-u', help='Update - Check for newer version of required files.\n  * Ignores other arguments.',
                    dest='update', action='store_true')
parser.add_argument('-U', help=argparse.SUPPRESS, dest='forceupdate', action='store_true')
parser.add_argument('-v', help='Verbose - Shows messages like spider status updates.', dest='verbose',
                    action='store_true')
parser.add_argument('-y', help=argparse.SUPPRESS, dest='y', action='store_true')
parser.add_argument('--sslv', help='Assess the SSL security of each target.\n   [considered intrusive]',
                    dest='sslopt', action='store_true')

group = parser.add_argument_group(" ENUMERATION")
group.add_argument('--dns', help='Use Bing for reverse DNS lookups.', dest='dns', action='store_true')
# group.add_argument('--dorks', help='Use Google filetype: to pull common doctypes.', dest='dorks', action='store_true')
group.add_argument('-o', help="Make an 'OPTIONS' call to grab the site's available\n methods.", dest='getoptions',
                   action='store_true')
group.add_argument('-r', help='Make an additional web call to get "robots.txt"', dest='getrobots', action='store_true')
group.add_argument('-x', help='Make an additional web call to get "crossdomain.xml"', dest='getcrossdomain',
                   action='store_true')
group.add_argument('--downgrade', help='Make requests using HTTP 1.0', dest='ver_dg', action='store_true')
group.add_argument('--noss', help='Disable screenshots.', dest='noss', action='store_true')
group.add_argument('--proxy', metavar="<[username:password@]ip:port[+type] | filename>",
                   help="Push all traffic through a proxy.\n  Supported types are socks and http," +
                        "basic, digest.\nFile should contain proxy info on one line.\n" +
                        "   example -  'username:password@127.0.0.1:9050+socks'\n", dest='proxy_dict')
group.add_argument('--proxy-auth', help='Specify authentication for the proxy at runtime with\n getpass.',
                   dest='proxy_auth', action='store_true')
group.add_argument('--spider', dest='crawl', action='store_true',
                   help="Enumerate all urls in target's HTML, create site layout\n graph." +
                        "  Will record but not follow links outside of\n the target's domain." +
                        "  Creates a map (.png) for that\n site in the <logfolder>/maps folder.")
group.add_argument('--alt-domains', metavar="<domains>",
                   help="Enable cross-domain spidering on specific domains.\n  (comma-seperated)", dest='alt_domains')
group.add_argument('--blacklist-urls', metavar="<file>",
                   help="Blacklist specific urls during crawl. Requires a\n line-seperated input list.",
                   dest='spider_url_blacklist')
group.add_argument('--mirror', dest='mirror', action='store_true',
                   help="Crawl and create a cached copy of sites, stored in\n the 'mirrored_sites' folder." +
                        "  Note: This will initiate\n a crawl, so --spider is not necessary.\n" +
                        " Any regular spidering options can still be\n  specified using the options above.")
group.add_argument('--useragent', dest='useragent', metavar="<string|file>",
                   help='Use a custom user agent. Default is in' +
                        " settings.py.\n  Accepts a line-delimited list of useragent strings.\n  ** This will" +
                        " exponentially increase the number\n   of interfaces! **", default=useragent)

group = parser.add_mutually_exclusive_group()
group.add_argument('-S', metavar="(1-5)",
                   help="Use a pre-set crawl aggression level.\n   Levels are listed in settings.py.", dest='crawl_level',
                   type=int)
group.add_argument('--spider-opts', dest='crawl_opts', metavar="<options>",
                   help="Provide custom settings for crawl.\n" +
                        "s='follow subdomains', d=depth, l='url limit'\nt='crawl timeout', u='url timeout'," +
                        " th='thread limit'\n        Example: --spider-opts s:false,d:2,l:500,th:1")

group = parser.add_argument_group(" OUTPUT")
group.add_argument('-d', metavar="<folder>", help='Directory in which to create log folder\n   [default is "./"]',
                   dest='logdir')
group.add_argument('-q', '--quiet', help="Won't show splash screen.", dest='quiet', action='store_true')
group.add_argument('-z', help='Compress log folder when finished.', dest='compress_logs', action='store_true')
group.add_argument('--json', help='stdout will include only JSON strings.  Log folders and\n' +
                   ' files are created normally.', dest='json', action='store_true')
group.add_argument('--json-min', help='The only output of this script will be JSON strings to\n stdout.', dest='json_min',
                   action='store_true')
group.add_argument('--notify', nargs='?', metavar="email address",
                   help='Send an email or SMS notification via sendmail when\n scan is complete.' +
                        ' Specifying a recipient email address\n is not necessary if one is defined in' +
                        ' settings.py.\n   (Requires configuration in conf/settings.py)', dest='notify')
group.add_argument('--parsertest', help='Will parse inputs, display the first 3, and exit.', dest='parsertest',
                   action='store_true')

group = parser.add_argument_group(" REPORTING")
group.add_argument('-e', help='Exclude default username/password data from output.', dest='defpass',
                   action='store_false', default=True)
group.add_argument('--logo', metavar="<file>", help='Specify a logo file for the HTML report.', dest='logo')
group.add_argument('--title', metavar='"Title"', help='Specify a custom title for the HTML report.', dest='title',
                   default=report_title)

opts = parser.parse_args()

if len(sys.argv) == 1:
    print(banner)
    parser.print_usage()
    print('\n')
    exit()

if opts.y:
    import random

    i = words.split(':')
    e = "%s %s of %s %s" % (random.choice(i[0].split(',')), random.choice(i[1].split(',')),
                            random.choice(i[2].split(',')), random.choice(i[3].split(',')))
    e = (" " * (18 - len(e) / 2)) + e + (" " * (18 - len(e) / 2))
    print(banner.replace("  Rapid Assessment of Web Resources ", e[0:36]))
    exit()


# Fill the opts with values from the config file if possible.
if 'target_input' in opts and opts.target_input.endswith(".cfg"):
    import ConfigParser

    config = ConfigParser.RawConfigParser()
    try:
        config.read(opts.target_input)

    except Exception, ex:
        parser.error("  %s[x]%s Error opening %s:\n\t%s." % (TC.RED, TC.END, opts.target_input, ex))
        sys.exit(1)

    for i in config.items('Settings'):
        if i[1] in ('True', 'False'):
            x = bool(i[1])
        else:
            x = i[1]

        vars(opts)[i[0]] = x


# Remove the big dinosaur...  :\
if not (opts.quiet or opts.json or opts.json_min):
    print(banner)


# Make sure we have PhantomJS or Ghost... or that we don't need either.
pjs_path = False
if not opts.noss and not use_ghost:
    # Get PhantomJS path
    if inpath("phantomjs"):  # installed elsewhere on the system
        pjs_path = "phantomjs"

    elif os.path.exists("%s/data/phantomjs/bin/phantomjs" % scriptpath):  # the rawr/data folder
        pjs_path = "%s/data/phantomjs/bin/phantomjs" % scriptpath

    elif platform_type in "CYGWIN|Windows" and inpath("phantomjs.exe"):  # Windows, installed elsewhereon system
        pjs_path = "phantomjs.exe"

    elif platform_type in "CYGWIN|Windows" and (os.path.exists("%s/data/phantomjs/phantomjs.exe" % scriptpath)):
        pjs_path = "%s/data//phantomjs/phantomjs.exe" % scriptpath

    elif not any([opts.noss, use_ghost, opts.asm, opts.update, opts.forceupdate]):
        print("  %s[x]%s phantomJS not found in $PATH or in RAWR folder.  \n\n\tTry running 'rawr.py -u'\n\n\tOr"
              " run rawr without screenshots (--noss)\n\n  %s[x]%s Exiting... !!\n\n" %
              (TC.RED, TC.END, TC.RED, TC.END))
        sys.exit(1)


# Stop right here and update if applicable
if opts.update or opts.forceupdate:
    update(pjs_path, scriptpath, opts.forceupdate, use_ghost)

if os.path.exists(opts.target_input):
    opts.target_input = os.path.realpath(opts.target_input)

# Determine filenames for the log directory and log file
if opts.logdir:
    # redefine logdir based on user request
    logdir = os.path.realpath(opts.logdir) + "/log_%s_rawr" % timestamp

else:
    logdir = os.path.realpath("log_%s_rawr" % timestamp)

logfile = "%s/artifacts/rawr_%s.log" % (logdir, timestamp)

if os.path.isdir(opts.target_input):
    if opts.target_input.endswith('/'):
        opts.target_input += '*'

    else:
        opts.target_input += '/*'

elif '*' in opts.target_input.split('/')[-1]:
    opts.target_input = os.path.abspath('/'.join(opts.target_input.split('/')[0:-1])) + '/' + \
                        opts.target_input.split('/')[-1]


# This is for later - if this is a file, we want its absolute path...
ua_path = os.path.realpath(str(opts.useragent))
if opts.proxy_dict and os.path.isfile(os.path.abspath(opts.proxy_dict)):
    opts.proxy_dict = open(os.path.abspath(str(opts.proxy_dict))).read().strip()


# Create the log directory if it doesn't already exist.
newdir = False
if not opts.json_min:
    if not os.path.exists(logdir):
        os.makedirs(logdir)
        newdir = True

    os.chdir(logdir)

    if not os.path.exists("./artifacts"):
        os.makedirs("./artifacts")

    import ConfigParser

    config = ConfigParser.RawConfigParser()
    config.add_section('Settings')

    for opt in vars(opts).keys():
        if not vars(opts)[opt] == parser.get_default(opt):
            config.set('Settings', opt, vars(opts)[opt])

    with open('rawr_%s.cfg' % timestamp, 'wb') as configfile:
        config.write(configfile)


# Parse and set all spidering options if applicable
if any([opts.crawl_level, opts.crawl, opts.mirror, opts.crawl_opts]):
    opts.crawl = True
    if opts.crawl_level:
        sl = opts.crawl_level

    else:
        sl = 3  # default

    # Populate the default options
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
                        writelog("\n  %s[i]%s spider_follow_subdomains set to 'False'" % (TC.BLUE, TC.END), logfile,
                                 opts)

                    elif v.lower() in ("true", "t"):
                        opts.spider_follow_subdomains = True
                        writelog("\n  %s[i]%s spider_follow_subdomains set to 'True'" % (TC.BLUE, TC.END), logfile,
                                 opts)

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
                    #        opts.spider_url_max_hits = int(v)
                    #        writelog("\n  %s[i]%s spider_url_max_hits set to '%s'" %
                    #                 (TC.BLUE, TC.END, v), logfile, opts)

    except:
        print("      %s[!]%s Error with --spider_opts:  '%s'\n\n\t\t%s" %
              (TC.YELLOW, TC.END, opts.crawl_opts, traceback.format_exc().replace('\n', '\n\t\t')))
        exit()


# Determine path of logo if applicable
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


# Throw a warning if the title is going to make the HTML report look goofy.
if opts.title and len(opts.title) > 60:
    writelog("  %s[!]%s warning - The title specified is longer than 60 characters and might not show up properly." %
             (TC.YELLOW, TC.END), logfile, opts)

# Check for a user-defined list of user agents
#    we got the ua_path from opts.useragent right before creating and changing to the logdir.
if os.path.isfile(ua_path):
    ua_tmp = {}
    with open(ua_path) as f:
        for l in f:
            l = l.strip()
            if l:
                ua_tmp[l] = reduce(lambda x, y: x + y, map(ord, l))

    writelog("  %s[i]%s Using custom UserAgent list.  [%s entries]" % (TC.BLUE, TC.END, len(ua_tmp)), logfile, opts)
    opts.useragent = ua_tmp
    ua_tmp = None

else:
    if opts.useragent != useragent:
        writelog("  %s[i]%s Setting custom UserAgent - '%s'." % (TC.BLUE, TC.END, opts.useragent), logfile, opts)

    opts.useragent = {opts.useragent: reduce(lambda x, y: x + y, map(ord, opts.useragent))}


# Check for the DPE database file.
if opts.defpass:
    if os.path.isfile("%s/%s" % (scriptpath, DPE_FILE)):
        writelog("\n  %s[i]%s Located dpe_db.xml\n" % (TC.BLUE, TC.END), logfile, opts)

    else:
        writelog("  %s[!]%s Unable to locate %s. =-\n" % (TC.BLUE, TC.END, DPE_FILE), logfile, opts)
        choice = raw_input("\tContinue without the DPE Database? [Y|n] ").lower()
        defpass = False
        if (choice not in "yes") and choice != "":
            print("\n  %s[x]%s Exiting... \n\n" % (TC.RED, TC.END))
            sys.exit(2)


# Check for the IpToCountry list
if os.path.exists("%s/%s" % (scriptpath, IP_TO_COUNTRY)):
    writelog("\n  %s[i]%s Located IpToCountry.csv\n" % (TC.BLUE, TC.END), logfile, opts)

else:
    writelog("  %s[!]%s Unable to locate %s. =-\n" % (TC.YELLOW, TC.END, IP_TO_COUNTRY), logfile, opts)
    choice = raw_input("\tContinue without Ip to Country info? [Y|n] ").lower()
    defpass = False
    if (choice not in "yes") and choice != "":
        print("\n  %s[x]%s Exiting... \n\n" % (TC.RED, TC.END))
        sys.exit(2)


# Get the scan log started...
if not opts.json_min:
    msg = "\nStarted RAWR : %s\n     cmdline : %s\n\n" % (timestamp, " ".join(sys.argv))
    open(logfile, 'a').write(msg)  # Log created
    writelog("\n  %s[+]%s Log Folder created:\n      %s \n" % (TC.CYAN, TC.END, logdir), logfile,
             opts)  # Second log entry


# Set the HTTP version to 1.0 if so desired.
if opts.ver_dg:
    writelog("  %s[i]%s Downgrading all requests to HTTP/1.0...\n" % (TC.BLUE, TC.END), logfile, opts)
    import httplib  # requests uses urllib3, which uses httplib...

    httplib.HTTPConnection._http_vsn = 10
    httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'

# Establish proxy settings
if opts.proxy_dict:
    if '@' in opts.proxy_dict:  # see if we have creds inline
        x = opts.proxy_dict.split('@')
        un, pw = x[0].split(':')
        h, t = x[1].split('+')

    else:
        if opts.proxy_auth:
            un = raw_input("   Proxy Username: ")
            pw = getpass.getpass("   Proxy Password: ")

        else:
            un, pw = False, False

        h, t = opts.proxy_dict.split('+')

    if t == 'socks':
        import socks
        h, p = h.split(':')
        socks.set_default_proxy(socks.SOCKS5, h, int(p), True, un, pw)         
        socket.socket = socks.socksocket
        opts.proxy_dict = {}
        opts.proxy_auth = {}
        try:
            res = requests.get(proxy_test_url).content
            if not (opts.json or opts.json_min):
                print('\n  %s[i]%s  Your proxied IP is: %s' % (TC.BLUE, TC.END, res.split('Add to Fav')[0].split('<b>')[1].split('<br>')[0].strip()))

        except Exception, ex:
            print ex
            quit(1)          

    elif t in ('http', 'basic', 'digest'):
        opts.proxy_dict = {"http": "http://" + h, "https": "http://" + h}
        if un and pw:
            if t == 'basic':
                opts.proxy_auth = HTTPProxyAuth(un, pw)

            elif t == 'digest':
                opts.proxy_auth = HTTPDigestAuth(un, pw)                

        try:
            res = requests.get(proxy_test_url,
                               proxies=opts.proxy_dict,
                               auth=opts.proxy_auth).status_code
        except Exception, ex:       
            print("\n  %s[x]%s  Proxy test failed - %s\n" % (TC.RED, TC.END, ex))
            sys.exit(1)

        if res == 407:
            print("\n  %s[x]%s  Proxy test failed. \n" % (TC.RED, TC.END))
            sys.exit(1)

    else:
        print("\n  %s[x]%s  Unknown proxy type - %s. \n" % (TC.RED, TC.END, t))
        exit(1)

    if not (opts.json or opts.json_min):
        print("\n  %s[i]%s  Proxy test successful. \n" % (TC.BLUE, TC.END))


db, ints, opts = init(opts)  # define the unix_ts, ints, and db globally
is_NMap_input = False
tcount = 0

# Process user input 
if opts.target_input.startswith('http'):
    process_url(opts.target_input)

else:
    if (re.match('^[a-z0-9]+([\-\.][a-z0-9]+)*\.[a-z]{2,6}(:[0-9]{1,5})?(/.*)?$',
                 opts.target_input) or (re.match(NMAP_INPUT_REGEX, opts.target_input) and
                                        not re.match('([-][0-9]{1,3}[-])|(([,-].*[/]|[/].' +
                                                     '*[,-])|([*].*[/]|[/].*[*]))',
                                                     opts.target_input))):
        files = run_nmap(opts.target_input, opts, logfile)
        is_NMap_input = True

    elif "*" in opts.target_input or os.path.isdir(opts.target_input):  # Handle 'glob-friendly' input.
        files = []

        if os.path.isdir(opts.target_input):
            opts.target_input += "/*"

        for f in glob_recurse(opts.target_input):
            if os.path.splitext(f)[1] in ('.xml', '.csv', '.nessus'):  # this is open for discussion
                files.append(f)

        files = list(set(files))

    elif os.path.exists(opts.target_input):
        files = [opts.target_input]

    else:
        files = []
        for f in opts.target_input.split(','):
            if not os.path.isfile(os.path.abspath(f)):  # path not found
                print("\n  %s[x]%s Unable to locate: \n\t%s\n" % (TC.RED, TC.END, os.path.abspath(f)))

            else:
                files.append(f)

        files = list(set(files))

    if len(files) < 1:
        print("\n  %s[x]%s  No usable files specified. \n" % (TC.RED, TC.END))
        os.remove('rawr_%s.shelvedb' % timestamp)  # also remove logdir?
        db.close()
        sys.exit(1)

    if not (opts.json or opts.json_min):
        print("\n  %s[+]%s Found %s usable file(s). \n" % (TC.CYAN, TC.END, len(files)))

    tcount = 0
    for filename in files:
        count = 0
        writelog("\n  %s[>]%s Parsing: %s" % (TC.GREEN, TC.END, filename), logfile, opts)
        try:
            if filename.endswith(".csv"):
                with open(filename) as r:
                    head = ' '.join([r.next() for x in xrange(2)])

                if 'Asset Group:' in head:
                    writelog("       %s[Qualys Port Service CSV]%s" % (TC.BLUE, TC.END), logfile, opts)
                    count = parse_qualys_port_service_csv(filename)

                else:  # generic CSV
                    writelog("       %s[Generic CSV]%s" % (TC.BLUE, TC.END), logfile, opts)
                    count = parse_csv(filename)

            elif filename.endswith(".nessus"):
                r = etree.parse(filename)

                if len(r.xpath('//NessusClientData_v2')) > 0:
                    writelog("       %s[Nessus V2]%s" % (TC.BLUE, TC.END), logfile, opts)
                    count = parse_nessus_xml(r)

                else:
                    writelog("        %s[!]%s Unrecognized .nessus file format.\n\n" % (TC.YELLOW, TC.END), logfile,
                             opts)
                    continue

            elif filename.endswith(".xml"):
                r = etree.parse(filename)

                if len(r.xpath('//NexposeReport')) > 0:
                    writelog("       %s[NeXpose XML]%s" % (TC.BLUE, TC.END), logfile, opts)
                    count = parse_nexpose_xml(r)

                elif len(r.xpath('//NeXposeSimpleXML')) > 0:
                    writelog("       %s[NeXpose Simple XML]%s" % (TC.BLUE, TC.END), logfile, opts)
                    count = parse_nexpose_simple_xml(r)

                elif len(r.xpath('//ASSET_DATA_REPORT')) > 0:
                    writelog("       %s[Qualys Scan Report]%s" % (TC.BLUE, TC.END), logfile, opts)
                    count = parse_qualys_scan_report_xml(r)

                elif len(r.xpath('//nmaprun')) > 0:
                    writelog("       %s[NMap]%s" % (TC.BLUE, TC.END), logfile, opts)
                    count = parse_nmap_xml(r)

                elif len(r.xpath('//report[@extension="xml" and @type="scan"]')) > 0:
                    writelog("       %s[OpenVAS]%s" % (TC.BLUE, TC.END), logfile, opts)
                    count = parse_openvas_xml(r)

                else:
                    writelog("      %s[!]%s Unrecognized XML file.\n\n" % (TC.YELLOW, TC.END), logfile, opts)
                    continue

            else:
                # Check to see if this is an NMap-formatted input list,
                #   pulling out and processing URLs in the process.

                urls_present = False
                with open('.tmp', 'w') as wf:
                    with open(filename) as f:
                        c = 0
                        for i in f:
                            if (re.match('^[a-z0-9]+([\-\.][a-z0-9]+)*\.[a-z]{2,6}(:[0-9]{1,5})?(/.*)?$', i) or (
                                re.match(NMAP_INPUT_REGEX, i) and
                                    not re.match('([-][0-9]{1,3}[-])|(([,-].*[/]|' +
                                                 '[/].*[,-])|([*].*[/]|[/].*[*]))', i))):
                                c += 1
                                wf.write(i + '\n')

                            elif i.startswith("http"):  # pick up URLS in the list and process them seperately
                                count += process_url(i)
                                urls_present = True

                if c > 0:
                    is_NMap_input = True
                    fname = run_nmap("-iL .tmp", opts, logfile)
                    r = etree.parse(fname[0])
                    count += parse_nmap_xml(r)

                elif not urls_present:
                    writelog("      %s[!]%s Unrecognized Input list.\n" % (TC.YELLOW, TC.END), logfile, opts)
                    continue

                os.remove(".tmp")

            if count > 0:
                writelog("      %s[+]%s %s new interfaces added to DB.\n" % (TC.GREEN, TC.END, count), logfile, opts)
                tcount += count

            else:
                writelog("      %s[!]%s No new interfaces added to DB.\n" % (TC.YELLOW, TC.END), logfile, opts)

            if newdir and not opts.json_min:
                try:
                    shutil.copyfile(filename, "./artifacts/%s" % os.path.basename(filename))
                except:
                    pass

            if opts.json_min:
                os.remove(filename)

        except Exception:
            error = traceback.format_exc().replace('\n', '\n\t\t')
            error_msg(error)
            writelog("      %s[!]%s Unable to parse: \n\t\t Error: %s\n\n" % (TC.YELLOW, TC.END, error), logfile, opts)
            continue

if not opts.json_min:
    if tcount > 0:
        x = ''
        if tcount > 1:
            x = "s"

        writelog("\n\n  %s[+]%s Starting run with %s interface%s in the DB.\n" % (TC.BLUE, TC.END, tcount, x), logfile,
                 opts)

    if not newdir and not (
                glob("*.png") or glob("artifacts/images/*.png")):  # Look for and copy any images from previous scans
        # Create the folder for html resource files
        writelog("\n  %s[!]%s No thumbnails found in [%s/]\n      or in [.%s/artifacts/images/]. **\n" %
                 (TC.YELLOW, TC.END, os.getcwd(), os.getcwd()), logfile, opts)
        if not opts.noss:
            writelog("      Will take website screenshots during the enumeration. ", logfile, opts)

    else:
        png_files = glob("*.png")
        if not os.path.exists("artifacts/images") and (not opts.noss or len(png_files) > 0):
            os.mkdir("artifacts/images")

        for filename in glob("*.png"):
            newname = filename.replace(":", "_")
            os.rename(filename, "./artifacts/images/%s" % newname)

if len(ints) > 0 and not opts.json_min:
    writelog("\n  %s[>]%s Building Attack surface matrix" % (TC.GREEN, TC.END), logfile, opts)

    # create the attack surface matrix
    asm_f = "%s/rawr_%s_attack_surface.csv" % (logdir, timestamp)
    try:
        ports = {}
        for i in ints:
            new = "%3s.%3s.%3s.%3s" % tuple(i.split("."))
            ints[new] = ints.pop(i)

        for i in ints:
            for p in ints[i][1]:
                if p not in ports:
                    ports[p] = 1

                else:
                    ports[p] += 1

        pts = ports.keys()
        pts.sort(key=int)  # ports is a list of ports found while parsing files
        cols = ["IP", "HOSTNAME"] + pts + [" ", "TOTAL"]
        pts = None

        with open(asm_f, 'a') as f:
            f.write('"' + '","'.join(cols) + '"\n')  # write the column headers
            for ip in sorted(ints.keys()):  # ints is a list of interfaces found while parsing files
                line = [ip.replace(' ', ''), ints[ip][0]] + [" "] * (len(cols) - 3)
                for port in ints[ip][1]:
                    line[cols.index(port)] = "x"

                line.append(str(line.count("x")))
                f.write('"' + '","'.join(line) + '"\n')

            line = ["TOTAL"] + [" "] * len(cols)

            for port in ports:
                line[cols.index(port)] = str(ports[port])  # fill out the last line w/ count totals

            f.write('\n"' + '","'.join(line) + '"\n')
            ports = None

    except:
        error = traceback.format_exc()
        error_msg(error)
        writelog("\n  %s[!]%s Error creating attack surface matrix :\n\t%s\n" %
                 (TC.YELLOW, TC.END, error), logfile, opts)

    if opts.asm:  # quit after creating the asm
        print('\n\n')
        db.close()
        exit(0)

if q.qsize() > 0:
    if not opts.json_min:
        # Begin processing any hosts found
        shutil.copy("%s/data/report_template.html" % scriptpath, 'report_%s.html' % timestamp)

        with open('sec_headers_%s.html' % timestamp, 'a') as of:
            of.write("""<html>\n<head>\n<title>Security Headers Report</title>\n<style>\n""" +
                     """table,th,td{border-spacing: 0px;border: 1px solid black; text-align:center;""" +
                     """ font-size:85%; letter-spacing:1px;}\n""" +
                     """th{font-size:12px;font-weight:bold;background-color:f2f2f2;}\n""" +
                     """p{font-size:85%; margin: 5; padding: 0;}\n""" +
                     """h5{margin: 0; padding: -5;}\n""" +
                     """h6{margin: 0; padding: 0;}\n""" +
                     """</style></head>\n<body>\n<table>\n<tr><th style='background-color:""" +
                     """ffffff;'></th><th>access-control-allow-origin</th><th>content-""" +
                     """security-policy</th><th>server</th><th>strict-transport-security""" +
                     """</th><th>x-content-type-options</th><th>x-frame-options</th><th>""" +
                     """x-permitted-cross-domain-policies</th><th>x-powered-by</th><th>""" +
                     """x-xss-protection</th></tr>""")

        filedat = open('report_%s.html' % timestamp).read()
        if is_NMap_input:
            fname = "artifacts/rawr_%s.xml" % timestamp  # Make the link to NMap XML in our HTML report
            x = '<li><a class="textwds" onselect=False target="_blank" href="%s">NMap XML</a></li>' % fname
            filedat = filedat.replace('<!-- REPLACEWITHLINK -->', x)

            if os.path.exists(opts.target_input):
                report_range = os.path.basename(str(opts.target_input))

            else:
                report_range = str(opts.target_input)

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
                report_range = opts.target_input

        filedat = filedat.replace('<!-- REPLACEWITHDATE -->', datetime.datetime.now().strftime("%b %d, %Y"))
        filedat = filedat.replace('<!-- REPLACEWITHTITLE -->', opts.title)
        filedat = filedat.replace('<!-- REPLACEWITHRANGE -->', report_range)
        filedat = filedat.replace('<!-- REPLACEWITHTIMESTAMP -->', timestamp)
        filedat = filedat.replace('<!-- REPLACEWITHSECHEADERS -->', "sec_headers_%s.html" % timestamp)
        filedat = filedat.replace('<!-- REPLACEWITHFLIST -->', ("hist, ua_cksum, " + flist.replace('hist, ', '')))

        if opts.logo:
            shutil.copy(logo_file, "./html_res/")
            l = ('\n<img id="logo" height="80px" src="./artifacts/%s" />\n' % os.path.basename(logo_file))
            filedat = filedat.replace('<!-- REPLACEWITHLOGO -->', l)

        open('report_%s.html' % timestamp, 'w').write(filedat)

        if is_NMap_input:
            if os.path.exists("%s/data/nmap.xsl" % scriptpath):
                if not os.path.exists("./artifacts/nmap.xsl"):
                    shutil.copy("%s/data/nmap.xsl" % scriptpath, "./artifacts/nmap.xsl")

                for xmlfile in glob("rawr_*.xml"):
                    fileloc = re.findall(r'.*href="(.*)" type=.*', open(xmlfile).read())[0]
                    filedat = open(xmlfile).read().replace(fileloc, 'artifacts/nmap.xsl')
                    open(xmlfile, 'w').write(filedat)

                writelog(
                    "\n  %s[i]%s Copied nmap.xsl to %s\n\tand updated link in files.\n" % (TC.BLUE, TC.END, logdir),
                    logfile, opts)

            else:
                writelog("\n  %s[!]%s Unable to locate nmap.xsl.\n" % (TC.YELLOW, TC.END), logfile, opts)

        if not os.path.exists("rawr_%s_serverinfo.csv" % timestamp):
            open("rawr_%s_serverinfo.csv" % timestamp, 'w').write('"' + flist.replace(', ', '","') + '"')

        target_count = q.qsize()
        writelog("\n  %s[>]%s Beginning enumeration of [ %s ] target[s].\n" % (TC.GREEN, TC.END, target_count), logfile,
                 opts)

    # Create the output queue - prevents output overlap
    o = OutThread(output, logfile, opts)
    o.daemon = True
    o.start()

    # Create the main worker pool and get them started
    for i in range(nthreads):
        t = SiThread(db, timestamp, scriptpath, pjs_path, logfile, logdir, output, opts)
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
        if os.path.exists('meta_report_%s.html' % timestamp):
            filedat = open('report_%s.html' % timestamp).read()
            x = '<li><a class="textwds" onselect=False target="_blank" ' \
                'href="meta_report_%s.html">META Report</a></li>' % timestamp
            filedat = filedat.replace('<!-- REPLACEWITHMETALINK -->', x)
            with open('report_%s.html' % timestamp, 'w') as of:
                of.write(filedat + "</div></body></html>")

            with open('meta_report_%s.html' % timestamp, 'a') as of:
                of.write("</body></html>")

        else:
            with open('report_%s.html' % timestamp, 'a') as of:
                of.write("</div></body></html>")

        with open('sec_headers_%s.html' % timestamp, 'a') as of:
            of.write("""</table><br><br>\n<h5>Access Control Allow Origin (Access-Control-""" +
                     """Allow-Origin)</h5>\n<p>\nModern websites often include content dyn""" +
                     """amically pulled in from other sources online. SoundCloud, Flickr, """ +
                     """Youtube and many other important websites use a technique called """ +
                     """Cross Object Resource Sharing (CORS) to do so. Access Control Allow""" +
                     """ Origin is a header that is part of the "conversation" between the """ +
                     """site a that wants to include data from another site.\n</p>\n<h5>Content""" +
                     """ Security Policy (Content-Security-Policy)</h5>\n<p>Content Security """ +
                     """Policy (CSP) prevents cross site scripting by explicitly declaring to """ +
                     """browsers which script, media, stylesheets, etc are supposed to be run""" +
                     """ from your website. By whitelisting these resources, if an attacker is""" +
                     """ ever able to embed his evil code on your site, the browser will ignore""" +
                     """ it and visitors to your site will remain safe.\n</p>\n<h5>Cross Domain""" +
                     """ Meta Policy (X-Permitted-Cross-Domain-Policies)</h5>\n<p>This header""" +
                     """ tells Flash and PDF files which Cross Domain Policy files found on""" +
                     """ your site can be obeyed; yes, it's a policy about other policies!""" +
                     """</p>\n</p>\n<h5>Content Type Options (X-Content-Type-Options)</h5>""" +
                     """\n<p>Microsoft Internet Explorer (IE) and Google Chrome have the """ +
                     """ability to guess the type of content may be found in a file, a """ +
                     """process called "MIME-sniffing". Since the browser can be tricked """ +
                     """by an attacker into making the incorrect decision about types of """ +
                     """files it sees online, webmasters can tell IE/Chrome to not to sniff.""" +
                     """ That directive is called "nosniff" and it's communicated to via HTTP""" +
                     """ headers.</p>\n</p>\n<h5>Server Information (Server)</h5>\n<p>The """ +
                     """principle of least privilege says you only get access to stuff you """ +
                     """need access to. Often times there is no reason for a server to advertise""" +
                     """ its information via headers.  Removing the server header won't stop """ +
                     """attacks but can make them slightly more difficult.</p>\n</p>\n<h5>Strict""" +
                     """ Transport Security (Strict-Transport-Security)</h5>\n<p>Using the HSTS""" +
                     """ header tells browsers that they should first make requests to your site""" +
                     """ over HTTPS by default!</p>\n</p>\n<h5>Frame Options (X-Frame-Options)""" +
                     """</h5>\n<p>The X Frame Options header is designed to minimize the """ +
                     """likelihood that an attacker can use a clickjacking attack against your""" +
                     """ site. In a clickjacking attack, the bad guy places a frame that """ +
                     """invisibly renders your site over top of some other content below """ +
                     """that is tempting for users to click on. </p>\n</p>\n<h5>Powered """ +
                     """By Information (X-Powered-By)</h5>\n<p>The principle of least """ +
                     """privilege says you only get access to stuff you need access to. """ +
                     """Often times there is no reason to advertise your software version""" +
                     """ information via headers.  Removing the x-powered-by header won't """ +
                     """stop attacks but can make them slightly more difficult.</p>\n</p>\n""" +
                     """<h5>XSS Protection (X-XSS-Protection)</h5>\n<p>Tells browsers such """ +
                     """as IE and Chrome to be even more strict when they suspect an xss """ +
                     """attack.  The header can designate the browser to not render the page,""" +
                     """ try to remove/encode dangerous characters, or provide no additional""" +
                     """ protection.</p>\n<h6>Descriptions provided by""" +
                     """ <a href="https://securityheaders.com">https://securityheaders.com</a>""" +
                     """</h6></body></html>""")

        # Sort the csv by IP
        try:
            f = "rawr_%s_serverinfo.csv" % timestamp
            i = flist.lower().split(", ").index(csv_sort_col)
            data_list = [l.strip() for l in open(f)]
            headers = data_list[0]
            data_list = data_list[1:]
            if csv_sort_col == "ipv4":
                data_list.sort(key=lambda x: socket.inet_aton(x.split(",")[i].replace('"', '')))

            else:
                data_list.sort(key=lambda x: x.split(",")[i].replace('"', ''))

            open(f, 'w').write("%s\n%s" % (headers, "\n".join(data_list)))

        except:
            error = traceback.format_exc().replace('\n', '\n\t\t')
            error_msg(error)
            writelog("  %s[!]%s Failed to sort server info CSV.\n\t%s\n" % (TC.YELLOW, TC.END, error), logfile, opts)

        writelog("\n  %s[+]%s Report created in [%s/]\n" % (TC.CYAN, TC.END, os.getcwd()), logfile, opts)

        if opts.compress_logs:
            writelog("  %s[>]%s Compressing logfile...\n" % (TC.GREEN, TC.END), logfile, opts)
            logdir = os.path.basename(os.getcwd())
            os.chdir("../")
            try:
                if platform_type in "CYGWIN|Windows":
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

        if opts.notify:
            try:
                import smtplib

                if opts.notify:
                    notify["to"] = opts.notify

                else:
                    if notify["type"] != "email":
                        notify["to"] = notify["sms_number"] + notify["sms_carrier"]

                msg = "From: %s\nTo: %s\nSubject: %s\n\n%s\n" % (
                notify["from"], ", ".join(notify["to"]), notify["subject"], notify["body"])

                msg.replace("$SCOPE$", str(report_range))
                msg.replace("$DATE$", str(timestamp))
                msg.replace("$RESULT_COUNT$", str(target_count))
                msg.replace("$TITLE$", str(opts.title))

                smtp_server = smtplib.SMTP(notify["server"])
                smtp_server.sendmail(notify["from"], ", ".join(notify["to"]), msg)

                writelog("  %s[+]%s Notification sent. ++\n" % (TC.CYAN, TC.END), logfile, opts)
                smtp_server.quit()

            except Exception, ex:
                writelog("  %s[!]%s Failed to send notification.\n\t%s\n" % (TC.YELLOW, TC.END, ex), logfile, opts)
                try:
                    smtp_server.quit()
                except:
                    pass
                finally:
                    smtp_server = None

else:
    writelog("\n  %s[!]%s No data returned. \n\n" % (TC.YELLOW, TC.END), logfile, opts)

try:
    db.close()
except:
    pass

if not (opts.json or opts.json_min):
    elapsed = time.time() - start
    print "Time taken: ", elapsed, "seconds."

elif opts.json_min:
    try:
        os.remove('rawr_%s.shelvedb' % timestamp)
    except:
        pass
