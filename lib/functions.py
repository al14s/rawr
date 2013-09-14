
import os
import sys
import shutil
import tarfile
import platform
import subprocess
import requests
import signal
import re
import time
import threading
from Queue import Queue
from lxml import html, etree
from glob import glob
from datetime import datetime
from lib.constants import *
from conf.settings import useragent, flist, timeout, ss_delay, spider_depth, spider_follow_subdomains
from modules.default import *

# Import graphviz and pygraph if they're available
try:
	import gv
	sys.path.append('..')
	sys.path.append('/usr/lib/graphviz/python/')
	sys.path.append('/usr/lib64/graphviz/python/')
	from pygraph.classes.graph import graph
	from pygraph.classes.digraph import digraph
	from pygraph.algorithms.searching import breadth_first_search
	from pygraph.readwrite.dot import write
	foundgv = True

except Exception, ex:
	#print " !! %s > \n\t\tWe won't be spidering due to this... \n" % ex
	# We'll decline the '--spider' command if there was a problem importing gv or pygraph
	foundgv = False


binged = {}
binging = False

threads=[]
q = Queue()  # Create the main queue and parse the files for hosts, placing them in the queue
output = Queue()  # Create the output queue - prevents output overlap


class out_thread(threading.Thread):
	def __init__(self, logfile):
		threading.Thread.__init__(self)
		self.logfile = logfile
		global writelog

	def run(self): 
		while True:
			writelog(output.get(), self.logfile)
			output.task_done()
					

class sithread(threading.Thread):
	def __init__(self, timestamp, scriptpath, pjs_path, logdir, bing_dns, getoptions, getrobots, defpass, crawl, noss):
		threading.Thread.__init__(self)

		self.timestamp = timestamp
		self.scriptpath = scriptpath
		self.pjs_path = pjs_path
		self.logdir = logdir
		self.bing_dns = bing_dns
		self.noss = noss
		self.getoptions = getoptions
		self.getrobots = getrobots
		self.crawl = crawl
		self.defpass = defpass
		self.terminate = False
		self.busy = False

	def run(self):

		global binged
		global binging
		global q

		while not self.terminate:
			time.sleep(0.5)

			if not q.empty():
				data = ""
				self.busy = True
				target = q.get()
				#output.put("[DEBUG]  target pulled from queue: " + str(target))
				hostnames = []

				prefix = "http://"
				if 'tunnel' in target.keys():
					print target['tunnel']
					if any(s in target['tunnel'] for s in ["https","ssl"]):
						prefix = "https://"
					
				suffix = ":" + target['port']
				if any(s in target['port'] for s in ["80","443"]):
					suffix = ""

				if self.bing_dns == True and (not 'is_bing_result' in target.keys()):
					# Don't do Bing>DNS lookups for non-routable IPs
					routable = True		
					nrips = ["10.","172.","192.168.","127.16-31","169."]
					for nrip in nrips:
						if "-" in nrip:
							a = int(nrip.split(".")[1].split("-")[0])
							while not a <= int(nrip.split(".")[1].split("-")[1]):
								if target['ipv4'].startswith('.'.join(nrip.split('.')[0], str(a), '')):
									routable = False
								a += 1

						elif target['ipv4'].startswith(nrip):
							routable = False

					if routable:
						while binging:
							time.sleep(0.5)  # The intention here is to avoid flooding Bing with requests.

						if target['ipv4'] in binged.keys():
							output.put("[.] Bing>DNS\t: " + target['ipv4'] + "  -  pulling from cache...")
							hostnames = binged[target['ipv4']]
							#output.put("[DEBUG] pulled from cache:\n%s" % str(hostnames))

						else:						
							binging = True
							output.put("[@] Bing>DNS\t: " + target['ipv4'])
							try: 
								cookies = dict(SRCHHPGUSR='NRSLT=150')
								bing_res = (requests.get("http://www.bing.com/search?q=ip%3a" + target['ipv4'], cookies=cookies).text).split("sb_meta")
								for line in bing_res:
									res = re.findall(r".*<cite>(.*)</cite>.*", line)
									if res:
										hostnames.append(res[0].split('/')[0])

								binged[target['ipv4']] = hostnames
								#output.put("[DEBUG]  binged.keys() - " +  str(binged.keys()) )

							except Exception, ex: 
								output.put("[x] Bing>DNS\t: Error - %s" % ex)
								hostnames = []   # Just to make sure it's cleared out.

							binging = False

						if len(hostnames) == 0: 
							output.put("[x] Bing>DNS\t: found no DNS entries for %s" % (target['ipv4']))

						else:
							# remove any duplicates from our list of domains...
							seen = set()
							hostnames = [ x for x in hostnames if x not in seen and not seen.add(x)]
							output.put("[+] Bing>DNS\t: found %s DNS entries for %s" % (len(hostnames), target['ipv4']))

							for hostname in hostnames:
								new_target = target.copy()
								new_target['is_bing_result'] = True
								new_target['hostnames'] = [hostname.strip()]
								#output.put("[DEBUG]  target injected into queue: " + str(new_target))
								q.put(new_target)

					else:
						output.put("[-] %s is not a routable IP, skipping Bing>DNS for this host." % target['ipv4'] )


				if not 'is_bing_result' in target.keys():
					# Add the ip into the mix of hostnames
					target['hostnames'].append(target['ipv4'])

				for hostname in target['hostnames']:
					if hostname != "":
						target['url'] = prefix + hostname + suffix
						if suffix == "":
							port = " [" + target['port'] + "]"
						else:
							port = ""

						output.put("[>] Pulling\t: " + target['url'] + port)

						if not self.noss:
							screenshot(target, "%s/images" % self.logdir, self.timestamp, self.scriptpath, self.pjs_path, self.logdir)

						try:
							target['res'] = requests.get(target['url'], headers={"user-agent":useragent}, verify=False, timeout=timeout, allow_redirects=True)
							msg = "[+] Finished"

						except Exception, ex:
							if hasattr(ex, 'code'):
								target['res'] = ex.code
							elif hasattr(ex, 'reason'):
								target['res'] = ex.reason
							else:
								target['res'] = ex

							msg = "[x] Failed"

						if self.getoptions:
							res = (requests.options(target['url'], headers={"user-agent":useragent}, verify=False, timeout=timeout, allow_redirects=False))
							if 'allow' in res.headers:
								target['options'] = res.headers['allow']

							if "x-powered-by" in target['res'].headers:
								target['x-powered-by'] = target['res'].headers['x-powered-by']

						if self.getrobots:
							try:
								dat = requests.get("%s/robots.txt" % target['url'], verify=False, timeout=timeout, allow_redirects=False).text
								if dat.status_code == 200 and "llow:" in dat_content: 
									if not os.path.exists("robots"):
										os.makedirs("robots")

									open("./robots/%s_robots.txt" % target['hostname'], 'w').write(dat_content)
									output.put("   [r] Pulled robots.txt:  ./robots/%s_%s_robots.txt  " % (target['hostname'], target['port']))
									target['robots'] = "y"

								dat = None

							except Exception:
								pass

						if self.crawl == True:
							output.put("[+] Spidering\t: %s" % full_url)
							spider(foundgv, target, logdir, timestamp, urls)

						parsedata(target, self.logdir, self.timestamp, self.scriptpath, self.defpass)
						output.put(msg + "\t: " + target['url'] + " [" + target['port'] + "]")

				self.busy = False

				busy_count = 0
				for t in threads:
					if t.busy == True:
						busy_count += 1
	
				output.put(" [ Main queue size [ %s ] - Threads Busy/Alive [ %s/%s ] ] "%(str(q.qsize()),busy_count,str(threading.active_count()-2)))

				q.task_done()


def screenshot(target, destination, timestamp, scriptpath, pjs_path, logdir):
	filename = "%s/%s_%s_%s.png" % (destination, target['url'].split("/")[2].split(":")[0], timestamp, target['port'])
	err='.'

	try:
		log_pipe = open("%s/rawr_%s.log" % (logdir, timestamp), 'ab')
		start = datetime.now()
		process = subprocess.Popen([pjs_path, "--web-security=no", "--ignore-ssl-errors=yes", "--ssl-protocol=any", scriptpath + "/data/screenshot.js", target['url'] , filename, useragent, str(ss_delay)], stdout=log_pipe, stderr=log_pipe)
		while process.poll() is None:
			time.sleep(0.1)
			now = datetime.now()
			if (now - start).seconds > timeout+1:
				sig = getattr(signal, 'SIGKILL', signal.SIGTERM)
				os.kill(process.pid, sig)
				os.waitpid(-1, os.WNOHANG)
				err = ' - Timed Out.'
				break

		log_pipe.close()
		log_pipe = None
		process = None

		if os.path.exists(filename): 
			if os.stat(filename).st_size > 0:
				output.put('[>] Screenshot\t: [ %s ] >>\n   %s' % (target['url'], filename))
			else:
				output.put('[X] Screenshot\t: [ %s ] Failed - 0 byte file. Deleted.' % (target['url']))
				try:
					os.remove(filename)
				except:
					pass
		else:
			output.put('[X] Screenshot\t:  [ %s ] Failed%s' % (target['url'], err))

	except Exception, ex:
		print target
		output.put('[!] Screenshot\t:  [ %s ] Failed - %s' % (target['url'], ex))


def addtox(fname, val): 
	if fname.lower() in flist.lower().split(', '):
		x[flist.lower().split(", ").index(fname.lower())] = re.sub('[\n\r,]', '', str(val))


def spider(makePNG, origin, logdir, timestamp, urls=None):
	if not os.path.exists("maps"): os.makedirs("maps")

	coll = []
	urls_visited = []
	map_text = [origin]
	fname = origin.split("/")[2]

	if urls == None:
		urls = [origin]
	else:
		urls = list(set(urls))

	def recurse(url_t1, urls_t2, d, tabs):
		global logdir
		global fname
		global timestamp

		for url_t2 in urls_t2:
			if d > 0 and makePNG: 
				coll.append((url_t1, url_t2))

			open('%s/maps/%s_%s.txt' % (logdir, fname, timestamp), 'a').write("\n" + tabs + url_t2 )

			if len(url_t2.split("/")) > 2: 
				if spider_follow_subdomains == True:
					url_t2_hn = ".".join((url_t2.split("/")[2]).split(".")[-2:])
				else:
					url_t2_hn = url_t2.split("/")[2]

			if url_t2_hn in url_t1 and not url_t2 in urls_visited:
				urls_visited.append(url_t2)
				try:
					html = (requests.get(url_t2, headers={"user-agent":useragent}, verify=False, timeout=timeout, allow_redirects=True).text).replace("\n","")
					urls_t3_r = list(set(re.findall(URL_REGEX, html, re.I)))
					urls_t3=[]
					for url_t3 in urls_t3_r:
						urls_t3.append(url_t3)

					if len(urls_t3) > 0 and d > 0:
						recurse(url_t2, urls_t3, d-1, tabs + "\t")					

				except Exception, ex:
					pass


	recurse(origin, urls, spider_depth, "\t")

	if len(coll) > 0 and makePNG:
		# Graph creation
		gr = graph()

		c = []
		# Add nodes and edges
		for item in coll:
			c.append(item[0].replace(":","~").split("<")[0])
			c.append(item[1].replace(":","~").split("<")[0])

		gr.add_nodes(list(set(c)))

		for item in coll:
			try:
				gr.add_edge((item[0].replace(":","~").split("<")[0], item[1].replace(":","~").split("<")[0]))
			except Exception, ex:
				pass

		st, order = breadth_first_search(gr, root=origin.replace(":","~").split("<")[0])
		gst = digraph()
		gst.add_spanning_tree(st)
		dot = write(gst)

		gvv = gv.readstring(dot)

		gv.layout(gvv, 'dot')
		gv.render(gvv, 'png', str('%s/maps/%s_map_%s.png' % (logdir, fname, timestamp)))


def parsedata(target, logdir, timestamp, scriptpath, defpass):
	x=[" "] * len(flist.split(","))

	def addtox(fname, val): 
		if fname.lower() in flist.lower().split(', '):
			x[flist.lower().split(", ").index(fname.lower())] = re.sub('[\n\r,]', '', str(val))

	for i,v in target.items():
		addtox(i, target[str(i)])

	# identify country if possible
	if os.path.exists("%s/%s" % (scriptpath, IP_TO_COUNTRY)):
		ip = target['ipv4'].split('.')
		ipnum = (int(ip[0])*16777216) + (int(ip[1])*65536) + (int(ip[2])*256) + int(ip[3])
		for l in re.sub('[\"\r]', '', open("%s/%s" % (scriptpath, IP_TO_COUNTRY)).read()).split('\n'):
			try:
				if l != "" and (not "#" in l) and (int(l.split(',')[1]) > ipnum > int(l.split(',')[0])):
					addtox("country", "[%s]-%s" % (l.split(',')[4], l.split(',')[6]))
					break

			except Exception, ex:
				output.put("  -- Error parsing %s:  %s  --" % (ex, IP_TO_COUNTRY))


	# eat cookie now....omnomnom
	if len(target['res'].cookies) > 0:	
		try:
			os.mkdir("cookies")

		except:
			pass

		open("./cookies/%s_%s.txt" % (target['url'].split("/")[2].split(":")[0] ,target['port']), 'w').write(str(target['res'].cookies))
		addtox("cookies", len(target['res'].cookies))
		
	addtox("endurl", target['res'].url)

	if "server" in target['res'].headers:
		addtox("server", target['res'].headers['server'])

	addtox("encoding", target['res'].encoding)

	hist = []
	for h in target['res'].history: hist.append(h.url)

	if len(hist) > 0: addtox("history", hist)

	addtox("returncode", "[%s]" % str(target['res'].status_code))

	# parse the html for different element types
	# Thanks to A.G. for the lxml suggestion.
        cxt = html.fromstring(target['res'].content)
	for tag in ['meta', 'iframe', 'applet', 'object', 'script', 'title', 'embed']:
		v = 0
		for el in cxt.iter(tag):
			v += 1

		addtox(tag, v)

	# looking for urls, we don't want to be limited to specific types of elements.
	urls = []
	for url in re.findall(URL_REGEX, target['res'].text, re.I):
		urls.append(url.split("<")[0])

	addtox("urls", ';'.join(urls) )

	# Run through our user-defined regex filters.
	#  *** If a field isn't present in 'flist' (in the settings section), it won't be added at this time.
	for field, regxp, modtype in modules:
		# MODTYPE_CONTENT - returns all matches, seperates by ';'
		if modtype == 0:	
			addtox(field, ';'.join(re.findall(regxp, target['res'].text, re.I)) )

		# MODTYPE_TRUEFALSE - returns 'True' or 'False' based on regxp
		elif modtype == 1:
			if len(re.findall(regxp, target['res'].text, re.I)) > 0:
				addtox(field, "True")
			else:
				addtox(field, "False")

		# MODTYPE_COUNT - counts the number of returned matches
		elif modtype == 2:
			addtox(field, len(re.findall(regxp, target['res'].text, re.I)) )

		else:
			output.put("**  skipping %s - \"\"\"%s\"\"\"... invalid modtype" % (field, regxp) )


	if target['protocol'] == "ssl":   # need to verify this....
		if not target['ssl_data']:  
			1==2 # Go out and grab the SSL cert.  Placeholder for now...

		# Parse cert and write to file
		if not os.path.exists("ssl_certs"):
			os.mkdir("ssl_certs") 

		ssl_data = target['ssl_data']

		open("./ssl_certs/%s.cert" % (nmap.split(", ")[1]),'w').write(ssl_data)
		addtox("SSL_Cert-Raw", ssl_data)
		ssl_data = ssl_data.split('\n')
		addtox("SSL_Cert-Issuer", ssl_data[1].split(": ")[1])
		addtox("SSL_Cert-Subject", ssl_data[0].split(": ")[1])
		if "*" in ssl_data[0].split(": ")[1]:
			subject = ssl_data[0].split(": ")[1].split("*")[1]
		else:
			subject = ssl_data[0].split(": ")[1]

		if subject in nmap.split(', ')[0:3]: 
			addtox("SSL_Cert-Verified", "yes")

		addtox("SSL_Cert-KeyAlg", "%s%s"%(ssl_data[2].split(": ")[1],ssl_data[3].split(": ")[1]) )
		addtox("SSL_Cert-MD5", ssl_data[6].split(": ")[1].replace(" ",''))
		addtox("SSL_Cert-SHA-1", ssl_data[7].split(": ")[1].replace(" ",''))
		addtox("SSL_Cert-notbefore", ssl_data[4].split(": ")[1].strip())
		addtox("SSL_Cert-notafter", ssl_data[5].split(": ")[1].strip())
		try:
			notbefore = datetime.strptime(ssl_data[4].split(": ")[1].strip(" "), '%Y-%m-%d %H:%M:%S')
			notafter = datetime.strptime(ssl_data[5].split(": ")[1].strip(" "), '%Y-%m-%d %H:%M:%S')
			vdays = ( notafter - notbefore ).days
			if datetime.now() > notafter: 
				daysleft = "EXPIRED"

			else: 
				daysleft = ( notafter - datetime.now() ).days

		except ValueError:
			# some certificates have non-standard dates in these fields.  
			vdays = "unk"
			daysleft = "unk"

		addtox("SSL_Cert-ValidityPeriod", vdays)
		addtox("SSL_Cert-DaysLeft", daysleft)

	# check title, service, and server fields for matches in defpass file
	if defpass:
		defpwd = ""
		target['services'] = []
		for a in ['server','version-info','x-powered-by','title']:
			if a in target.keys():
				target['services'].append(target[a])

		with open("%s/%s" % (scriptpath, DEFPASS_FILE)) as f:
			for line in f:
				try:
					if not line.startswith("#"):
						if (line.split(',')[0].lower() in (target['services']) ): 
							defpwd += "%s;" % (':'.join(line.split(',')[0:5]))

				except Exception, ex:
					output.put(" -- Error parsing %s: %s --" % (DEFPASS_FILE, ex))

		if defpwd: 
			addtox("Default Password Suggestions", defpwd.strip(";"))

	open('index_%s.html' % timestamp, 'a').write("%s<br>" % str(','.join(x)))
	open("rawr_%s_serverinfo.csv" % timestamp, 'a').write("\n%s" % (str(','.join(x))))


def write_to_csv(timestamp, target):
	x=[" "] * len(flist.split(","))

	if not os.path.exists("rawr_%s_serverinfo.csv" % timestamp):
		open("rawr_%s_serverinfo.csv" % timestamp, 'w').write(flist)

	for i,v in target.items():
		addtox(i, target[str(i)])	

	try:
		open("rawr_%s_serverinfo.csv" % timestamp, 'a').write("\n%s" % (str(','.join(x))))

	except Exception, ex:
		print "\t\t    [!] Unable to write .csv !\n\t\t Error: %s\n\n" % ex
		print x


def parseNexposeXML(allinfo, timestamp, filename):
	data = etree.iterparse(filename)
	# Placeholder until I can research the format...
	targets = []
	for node in dom.getElementsbyTagName('node'):
		ip = node.getElementsbyTagName('address').firstChild.nodeValue
		hostname = node.getElementsbyTagName('name').firstChild.nodeValue

		# ????????????????

		if web:				
			targets.append(target)

		elif allinfo:
			write_to_csv(timestamp, target)

	return targets


def parseQualysXML(allinfo, timestamp, filename):
	data = etree.iterparse(filename)
	targets = []
	for host in dom.getElementsByTagName('HOST'):
		target = {}
		target['hostname'] = ""
		target['ipv4'] = host.getElementsByTagName('IP')[0].firstChild.nodeValue
		if len(host.getElementsByTagName('DNS')) > 0:
			target['hostname'] = host.getElementsByTagName('DNS')[0].firstChild.nodeValue

		for name in host.getElementsByTagName('NETBIOS'):
			if not name.firstChild.nodeValue.lower() in hostname.lower():
				target['hostname'] += "|" + name.firstChild.nodeValue

		for vuln in host.getElementsByTagName('VULN_INFO'):
			if vuln.getElementsByTagName('QID')[0].firstChild.nodeValue in "86000;86001":
				for name in vuln.getElementsByTagName('FQDN'):
					if not name.firstChild.nodeValue.lower() in hostname.lower():
						target['hostname'] += "|" + name.firstChild.nodeValue

				target['port'] = vuln.getElementsByTagName('PORT')[0].firstChild.nodeValue
				target['protocol'] = vuln.getElementsByTagName('PROTOCOL')[0].firstChild.nodeValue
				target['owner'] = ""
				target['service'] = vuln.getElementsByTagName('SERVICE')[0].firstChild.nodeValue
				target['sunrpc_info'] = ""
				target['version_info'] = (vuln.getElementsByTagName('RESULT')[0].firstChild.nodeValue).split("\t")[2]

				targets.append(target)

			elif allinfo:
				write_to_csv(timestamp, target) 

	return targets


def parseNessusXML(allinfo, timestamp, filename):
	data = etree.iterparse(filename)
	targets = []
	for node in dom.getElementsByTagName('ReportHost'): 
				for item in node.getElementsByTagName('ReportItem'):
					plugin = item.getAttribute('pluginName')
	 				if plugin == "Service Detection":
						target = {}
						target['hostname'] = node.getAttribute('name')

						for subele in node.getElementsByTagName('tag'):
							name = subele.getAttribute('name')
							val = subele.firstChild.nodeValue
							if name == "host-ip":
								target['ipv4'] = val
							elif name == "operating-system": 
								target['version_info'] = val
							elif name == "system-type": 
								target['service'] = val
							elif name == "netbios-name": 
								target['hostname'] += ("|" + val)

						target['version_info'] += " (%s)"%systype
			
						target['protocol'] = item.getAttribute('protocol')
						target['port'] = item.getAttribute('port')
						plugin_output = item.getElementsByTagName("plugin_output")[0].firstChild.nodeValue

						if item.getAttribute('svc_name') in ["www","http?","https?"]:
							target['protocol'] = "http"
							if any(s in plugin_output.lower() for s in ["ssl", "tls"]):
								target['protocol'] += "s"
							targets.append(target)

						elif allinfo:
							write_to_csv(timestamp, target)

	return targets


def parseNMapXML(r):
	targets = []
	for el_port in r.xpath("//port"):
		if el_port.find("state").attrib["state"] == "open":
			target = {}
			el_host = el_port.getparent().getparent()
			for el_add in el_host.xpath("address"):
				target[el_add.attrib['addrtype']] = el_add.attrib['addr']

			target['hostnames'] = []
			for el_hn in el_host.xpath("*/hostname"):
				target['hostnames'].append(el_hn.attrib['name'])

			for el_svc in el_port.xpath("service"):
				for key in el_svc.keys():
					target["service_"+key] = el_svc.attrib[key]
		
			for el_scpt in el_port.xpath("script"):
				if el_scpt.attrib['id'] == "ssl-cert":
					target['ssl-cert'] = el_scpt.attrib['output']

				if el_scpt.attrib['id'] == "ssl-enum-ciphers":
					target["SSL_Tunnel-Ciphers"] = el_scpt.attrib['output'].replace("\n",";")
					target["SSL_Tunnel-Weakest"] = el_scpt.attrib['output'][-1].strip('\n').strip()
			
			for el_hn in el_host.xpath('owner'):
				target['owner'].append(el_hn.attrib['name'])

			target['port'] = el_port.attrib['portid']
			target['protocol'] = el_port.attrib['protocol']

		if any(s in target['service_name'].lower() for s in ["ssl", "http", "tls"]):
			targets.append(target)

		elif allinfo:
			write_to_csv(target)
	
	return targets


def update(force, ckinstall, pjs_path, scriptpath):
	os.chdir(scriptpath)

	# remove any files left over from versions < 0.1.5
	#   we'll leave this in until 0.1.6
	for pre_ver5_file in ["CHANGELOG","README","LICENSE","report_template.html","screenshot.js","nmap.xsl","jquery.js","defpass.csv","IpToCountry.csv"]:
		if os.path.exists(pre_ver5_file): os.remove(pre_ver5_file)

	if os.path.exists("phantomjs"):
		def onerror(func, path, exc_info):
			if not os.access(path, os.W_OK):
				os.chmod(path, stat.S_IWUSR)
				func(path)

		shutil.rmtree("phantomjs",onerror=onerror)


	url = REPO_DL_PATH + VER_FILE
	print "  ++ Checking current versions...  >\n   %s\n"%url
	try:
		ver_data = requests.get(url).text
		script_ver = ver_data.split(",")[0].split(":")[0].replace('\n','')
		script_files = ver_data.split(",")[0].split(":")[1:]
		defpass_ver = ver_data.split(",")[1].replace('\n','')
		ip2c_ver = ver_data.split(",")[2].replace('\n','')
		pJS_ver = ver_data.split(",")[3].replace('\n','')

	except Exception, ex:
		print "  !! Failed:  %s\n"%ex
		sys.exit(1)

	# check for updated version of script
	if script_ver > VERSION:
		choice = raw_input('\n  ** Update RAWR v%s to v%s? [Y/n]:' % (VERSION, script_ver))
		if (choice.lower() in ("y","yes",'')):
			print "\n  ++ Updating  RAWR v%s >> v%s\n" % (VERSION, script_ver)
			url = REPO_DL_PATH + "rawr_" + script_ver + ".tar"
			print "\tPulling - " + url
			try:
				data = requests.get(url).content
				open("rawr_" + script_ver + ".tar", 'w+b').write(data)
				tarfile.open("rawr_" + script_ver + ".tar").extractall('../')
				os.remove("rawr_" + script_ver + ".tar")

			except Exception, ex:
				print "\n    !! Error pulling: " + url + "\n\t\t - " + str(ex)
				print "     Try pulling lastest version from %s\n\n" & REPO_DL_PATH
				sys.exit(1)

			print "\n     ++ Update successful.  Restarting script... ++  \n\n"
			time.sleep(3)
			python = sys.executable
			os.execl(python, python, * sys.argv)
		else:
			print "\n  ++ RAWR v%s found (current is %s) ++\n" % (VERSION, script_ver)

	else:
		print "  ++ RAWR v%s found (current) ++\n" % VERSION


	if ckinstall:
		# nmap
		if not (inpath("nmap") or inpath("nmap.exe")):
			print "  !! NMap not found in $PATH.  You'll need to install it to use RAWR.  \n"
		else:
			proc = subprocess.Popen(['nmap','-V'], stdout=subprocess.PIPE)
			ver = proc.stdout.read().split(' ')[2]
			main_ver = ver.split('.')[0]
			if int(main_ver) < 6: 
				print "  ** NMap %s found, but versions prior to 6.00 won't return all SSL data. **\n"%ver
			else:
				print "  ++ NMap %s found ++\n"%ver

		try:
			proc = subprocess.Popen([pjs_path,'-v'], stdout=subprocess.PIPE)
			pJS_curr = re.sub('[\n\r]', '', proc.stdout.read())
		except:
			pJS_curr = ""

		if force or (pJS_ver > pJS_curr) or not (inpath("phantomjs") or inpath("phantomjs.exe") or os.path.exists("data/phantomjs/bin/phantomjs") or os.path.exists("data/phantomjs/phantomjs.exe")):
			if not force:		
				if pJS_curr != "" and (pJS_ver > pJS_curr):
					txt = '\n  !! phantomJS %s found (current is %s) - do you want to update? [Y/n]: '%(pJS_curr,pJS_ver)
					choice = raw_input(txt)
				else:
					choice = raw_input('\n  !! phantomJS was not found - do you want to install it? [Y/n]: ')
					if not (choice.lower() in ("y","yes",'')): 
						print "\n  !! Exiting...\n\n"
						sys.exit(0)
			
			if force or (choice.lower() in ("y","yes",'')): 
				# phantomJS
				pre = "phantomjs-%s"%pJS_ver
				if  platform.system() in "CYGWIN|Windows": 
					fname = pre+"-windows.zip"
				elif platform.system().lower() in "darwin": 
					fname = pre+"-macosx.zip"
				elif sys.maxsize > 2**32: 
					fname = pre+"-linux-x86_64.tar.bz2"
				else: 
					fname = pre+"-linux-i686.tar.bz2"  # default is 32bit *nix

				url = "%s%s"%(PJS_REPO, fname)
				print "\n  ++ Pulling/installing phantomJS >\n   %s"%url

				try:
					fname = "data/" + fname
					data = requests.get(url).content
					open(fname,'w+b').write( data )

					if os.path.exists("data/phantomjs"):
						def onerror(func, path, exc_info):
							if not os.access(path, os.W_OK):
								os.chmod(path, stat.S_IWUSR)
								func(path)

						shutil.rmtree("data/phantomjs",onerror=onerror)

					if fname.endswith(".zip"):
						import zipfile
						zipfile.ZipFile(fname).extractall('./data')
					else: 
						tarfile.open(fname).extractall('./data')		
				
					os.rename(str(os.path.splitext(fname)[0].replace(".tar",'')), "data/phantomjs")
					os.remove(fname)

					if platform.system().lower() in "darwin": 
						os.chmod("data/phantomjs/bin/phantomjs",755)
						# Mac OS X: Prevent showing the icon on the dock and stealing screen focus.
						#   http://code.google.com/p/phantomjs/issues/detail?id=281
						f = open("data/phantomjs/bin/Info.plist",'w')
						f.write(OSX_PLIST)
						f.close()
					
					print "     ++ Success ++\n"
				except Exception, ex:
					print "  !! Failed:  %s\n"%ex

		else:
			print "  ++ phantomJS %s found (current supported version) ++\n"%pJS_curr


	defpass_curr = 0
	if os.path.exists(DEFPASS_FILE):
		ofile = open(DEFPASS_FILE).readlines()
		for line in ofile:
			if line.startswith("#"):
				defpass_curr = line.split(' ')[1].replace('\n','')

	if not os.path.exists(DEFPASS_FILE) or force or (defpass_ver > defpass_curr):
		# defpass
		url = REPO_DL_PATH + DEFPASS_FILE.split("/")[1]
		print "  ++ Updating %s rev.%s >> rev.%s\n   %s" % (DEFPASS_FILE, defpass_curr, defpass_ver, url)
		try:
			data = requests.get(url).content
			open("data/defpass_tmp.csv",'w').write( data )
			try: 
				os.remove(DEFPASS_FILE)
			except: 
				pass

			os.rename("data/defpass_tmp.csv", DEFPASS_FILE)
			c = 0 
			for line in open(DEFPASS_FILE).read().split('\n'):
				c += 1

			print "     ++ Success - (Contains %s entries)  ++" % c
		except Exception, ex:
			print "     !! Failed:  %s\n" % ex
	else:
		print "     -- NOT updating %s - already at rev.%s" % (DEFPASS_FILE, defpass_ver)

	ip2c_curr = 0
	if os.path.exists(IP_TO_COUNTRY):
		ofile = open(IP_TO_COUNTRY).readlines()
		for line in ofile:
			if "# Software Version" in line:
				ip2c_curr = line.split(" ")[5].replace('\n','')
				break

	if not os.path.exists(IP_TO_COUNTRY) or force or (ip2c_ver > ip2c_curr):
		# IpToCountry
		url = REPO_DL_PATH + IP_TO_COUNTRY.split("/")[1] + ".tar.gz"
		print "\n  ++ Updating %s ver.%s >> ver.%s\n   %s" % (IP_TO_COUNTRY, ip2c_curr,ip2c_ver,url)
		try:
			data = requests.get(url).content
			open(IP_TO_COUNTRY + ".tar.gz",'w+b').write( data )
			tarfile.open(IP_TO_COUNTRY + ".tar.gz").extractall('./data')
			os.remove(IP_TO_COUNTRY + ".tar.gz")
			print "     ++ Success ++\n"

		except Exception, ex:
			print "     !! Failed:  %s\n" % ex
			sys.exit(1)
	else:
		print "\n     -- NOT updating %s - already at ver.%s\n" % (IP_TO_COUNTRY, ip2c_ver)

	print "  ++  Update Complete  ++\n\n"
	sys.exit(2)


def inpath(app):
	for path in os.environ["PATH"].split(os.pathsep):
		exe_file = os.path.join(path, app)
		if os.path.isfile(exe_file) and os.access(exe_file, os.X_OK):
			return exe_file


def writelog(msg, logfile):
	print msg
	open(logfile, 'a').write(msg + "\n")

