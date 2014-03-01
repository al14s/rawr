# Report settings
report_title = "Web Interface Enumeration Results"  # default title if '--title' is not specified

# Scan settings
timeout = 15          # timeout in seconds for each web call (screenshots and geturl)
ss_delay = 1          # delay in seconds or page to render before screenshot
nmapspeed = 4         # nmap
nthreads = 25         # number of threads for the info run
useragent = 'Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US)'  # for the info run and screenshots.
ports = "80,443,8080,8088,8443"	 # default scan ports
fuzzdb = "66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,2301,3128,3306,4000,4001" + \
    ",4002,4100,5000,5432,5800,5801,5802,6346,6347,7001,7002,8080,8088,8443,8888,30821"
# http://code.google.com/p/fuzzdb/source/browse/trunk/wordlists-misc/common-http-ports.txt

# Spidering options
spider_follow_subdomains = True     # Allows all subdomains of given url.
spider_depth = 3                    # Number of layers to crawl.  ex: www.domain.com/1/2/3.html
spider_timeout = 180                # Time in seconds after which the crawl will cease.
spider_url_limit = 300              # Maximum number of urls to crawl.
#spider_url_max_hits = 15            # Maximum number of times to hit a single url - not incl. variables

# CSV settings
csv_sort_col = "ipv4"     # The column name of the field by which the CSV will be ordered.  *Must exist in 'flist'*
flist = "url, ipv4, port, x-powered-by, options, returncode, hostnames, notes, Title, version, " + \
        "allow, cookies, Robots, iframe, applet, object, script, embed, file_includes, " + \
        "Access-Control-Allow-Origin, Content-Security-Policy, X-Permitted-Cross-Domain-Policies, " + \
        "X-Content-Type-Options, Strict-Transport-Security, X-XSS-Protection, X-Frame-Options, " + \
        "SSL_Cert-DaysLeft, SSL_Cert-ValidityPeriod, SSL_Cert-MD5, SSL_Cert-SHA-1, SSL_Cert-notbefore, " + \
        "SSL_Cert-notafter, country, service_version, Server, robots.txt, rpc_info, endURL, Date, " + \
        "analytics_ID, owner, Content-MD5, Content-Type, Last-Modified, Trailer, Transfer-Encoding, " + \
        "Warning, WWW-Authenticate, Proxy-Authenticate, Age, Keywords, " + \
        "Description, Author, Revised, docs, passwordFields, email_addresses, HTML5, comments, Defpass, diagram"
# 'flist' contains the column headers for the csv generated post-scan.
#     Add, Rearrange, or Remove fields as desired.
#     Tip: 'notes' is not a field used in html headers and will contain no data,
#            so it can be used for entering notes during followup.
#
# DISABLED COLUMNS (use the line below to store columns you don't want to see in the csv):
# 	doc_count, SSL_Tunnel-CiphersRaw, protocol, form_start, info, SSL_Cert-KeyAlg, SSL_Tunnel-Ciphers,
# SSL_Tunnel-Weakest, SSL_Cert-Raw, SSL_Cert-Subject, SSL_Cert-Verified, SSL_Cert-Issuer, x-aspnet-version
# Cache-Control, Connection, Content-Encoding, Content-Language, Content-Length, meta, Content-Location,

