
# Report settings
report_title = "Web Interface Enumeration Results"	# default title if '--title' is not specified


# Scan settings
timeout =      20        # timeout in seconds for each web call (screenshots and geturl)
ss_delay =      1         # delay in seconds or page to render before screenshot
nmapspeed =     4         # nmap
nthreads =     25        # number of threads for the info run
useragent =    'Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/7.0'	# for the info run and screenshots.  This is sensitive!
ports =        "80,443,8080,8088,8443"	 # default scan ports
fuzzdb =       "66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,2301,3128,3306,4000,4001,4002,4100,5000,5432,5800,5801,5802,6346,6347,7001,7002,8080,8888,30821"
#http://code.google.com/p/fuzzdb/source/browse/trunk/wordlists-misc/common-http-ports.txt
spider_depth =  3
spider_follow_subdomains = False     # Allows all subdomains of given url.  Recommended for internal engagements - use caution.


# CSV settings
csv_sort_col =  "host_ip"     # The column name of the field by which the CSV will be ordered.  *Must exist in 'flist'*
flist =         "url, host_ip, port, returncode, hostname, notes, Title, version, allow, cookies, JQuery, IFrames, Java_Applets, Flash_Objects, file_includes, SSL_Cert-KeyAlg, SSL_Tunnel-Ciphers, SSL_Tunnel-Weakest, SSL_Cert-DaysLeft, SSL_Cert-ValidityPeriod, SSL_Cert-MD5, SSL_Cert-SHA-1, SSL_Cert-notbefore, SSL_Cert-notafter, state, protocol, country, service, robots.txt, rpc_info, endURL, Date, Server, analytics_ID, owner, Content-MD5, Content-Type, Last-Modified, Trailer, Transfer-Encoding, Warning, X-XSS-Protection, X-Frame-Options, WWW-Authenticate, Proxy-Authenticate, Age, Robots, Keywords, Description, Author, Revised, form_start, passwordFields, emailAddresses, HTML5, info, Default Password Suggestions"
# 'flist' contains the column headers for the csv generated post-scan.  
#     Add, Rearrange, or Remove fields as desired.
#     Tip: 'notes' is not a field used in html headers and will contain no data, 
#            so it can be used for entering notes during followup.
#
# DISABLED COLUMNS (use the line below to store columns you don't want to see in the csv):
# 	SSL_Tunnel-CiphersRaw, SSL_Cert-Raw, SSL_Cert-Subject, SSL_Cert-Verified, SSL_Cert-Issuer, Cache-Control, Connection, Content-Encoding, Content-Language, Content-Length, meta, Content-Location, 


# Some default variable defs
nmapout = ""
nmap_il = ""
sslopt = ""
nmaprng = ""
sourceport = ""
logo_file = ""
files = []
binged = []
binging = False
quiet = False
defpass = True
newdir = False
xmlfile = False
bing_dns = False
getrobots = False
getoptions = False
ver_dg = False
allinfo = False
crawl = False
compress_logs = False
upd = False
