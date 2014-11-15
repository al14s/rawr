# Report settings
report_title = "Web Interface Enumeration Results"  # default title if '--title' is not specified

# Scan settings
timeout = 30            # timeout in seconds for each web call (screenshots and geturl)
use_ghost = False       # If set to False, RAWR will use PhantomJS
ss_delay = 2            # delay in seconds or page to render before screenshot
nmapspeed = 4           # nmap -T<n> setting
nthreads = 25           # number of threads for the info run
allow_redir = True      # Allow redirects for non-spidering calls
useragent = 'Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US)'  # for the info run and screenshots.
ports = "80,443,8080,8088,8443"	 # default scan ports
fuzzdb = "66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,2301,3128,3306,4000,4001" + \
    ",4002,4100,5000,5432,5800,5801,5802,6346,6347,7001,7002,8080,8088,8443,8888,30821"
# http://code.google.com/p/fuzzdb/source/browse/trunk/wordlists-misc/common-http-ports.txt

# Spider aggression presets.
#  follow links to subdomains
#  folder depth
#  process timeout
#  url timeout
#  url limit
#  thread limit
#  breadth first
#  url max hits
spider_levels = {1: (False, 2, 200, 3, 100, 2, True, 5),
				 2: (False, 2, 250, 4, 150, 3, True, 5),
				 3: (True, 3, 300, 5, 300, 5, True, 7),
				 4: (True, 7, 400, 10, 300, 7, True, 10),
				 5: (True, 15, 500, 30, 500, 10, True, 15)}

# CSV settings
csv_sort_col = "ipv4"     # The column name of the field by which the CSV will be ordered.  *Must exist in 'flist'*
flist = "url, ipv4, port, x-powered-by, options, returncode, hostnames, notes, title, version, allow, " + \
		"cookies, robots, iframe, applet, object, script, embed, file_includes, access-control-allow-origin, " + \
		"content-security-policy, x-permitted-cross-domain-policies, x-content-type-options, " + \
		"strict-transport-security, x-xss-protection, x-frame-options, ssl_cert-daysleft, " + \
		"ssl_cert-validityperiod, ssl_cert-md5, ssl_cert-sha-1, ssl_cert-notbefore, ssl_cert-notafter, " + \
		"country, type, cpe, cve, service_version, server, robots.txt, rpc_info, endurl, date, analytics_id, owner, " + \
		"content-md5, content-type, last-modified, trailer, transfer-encoding, warning, www-authenticate, " + \
		"proxy-authenticate, age, keywords, dpe_description, description, author, revised, docs, passwordfields, " + \
		"email_addresses, html5, comments, defpass, diagram"
# 'flist' contains the column headers for the csv generated post-scan.
#     Add, Rearrange, or Remove fields as desired.
#     Tip: 'notes' is not a field used in html headers and will contain no data,
#            so it can be used for entering notes during followup.
#
# DISABLED COLUMNS (use the line below to store columns you don't want to see in the csv):
# 	doc_count, SSL_Tunnel-CiphersRaw, protocol, form_start, info, SSL_Cert-KeyAlg, SSL_Tunnel-Ciphers,
# SSL_Tunnel-Weakest, SSL_Cert-Raw, SSL_Cert-Subject, SSL_Cert-Verified, SSL_Cert-Issuer, x-aspnet-version
# Cache-Control, Connection, Content-Encoding, Content-Language, Content-Length, meta, Content-Location,
