
import os
import sys
import shutil
import tarfile
import urllib2
import platform
import subprocess
import signal
import re
import time
import threading
from glob import glob
from xml.dom import minidom
from datetime import datetime
from lib.constants import *
from conf.settings import useragent, flist, timeout, ss_delay, binged, binging, spider_depth, spider_follow_subdomains
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
	print " !! %s > \n\t\tWe won't be spidering due to this... \n" % ex
	# We'll decline the '--spider' command if there was a problem importing gv or pygraph
	foundgv = False


class out_thread(threading.Thread):
	def __init__(self, queue, logfile):
		threading.Thread.__init__(self)
		self.queue = queue
		self.logfile = logfile
		global writelog

	def run(self): 
		while True:
			writelog(self.queue.get(), self.logfile)
			self.queue.task_done()
					

class sithread(threading.Thread):
	def __init__(self, q, threads, opener, timestamp, scriptpath, pjs_path, logdir, output, bing_dns, getoptions, getrobots, defpass, crawl):
		threading.Thread.__init__(self)

		self.timestamp = timestamp
		self.threads = threads
		self.scriptpath = scriptpath
		self.pjs_path = pjs_path
		self.logdir = logdir
		self.bing_dns = bing_dns
		self.output = output
		self.getoptions = getoptions
		self.getrobots = getrobots
		self.crawl = crawl
		self.q = q
		self.defpass = defpass
		self.terminate = False
		self.busy = False
		self.opener = opener

	def run(self):

		global binged
		global binging

		while not self.terminate:
			time.sleep(0.5)
			if not self.q.empty():
				data = ""
				self.busy = True
				nmap = self.q.get().split(', ')

				hostnames = []

				prefix = "http://"
				if any(s in nmap[6] for s in ["https","ssl"]):
					prefix = "https://"
					
				suffix = ":"+nmap[2]
				if any(s in nmap[2] for s in ["80","443"]):
					suffix = ""
				
				if self.bing_dns == True and not "bing~" in nmap[0]:
					# Don't do Bing>DNS lookups for non-routable IPs
					routable = True		
					nrips = ["10.","172.","192.168.","127.;16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31","169."]
					for nrip in nrips:
						if nmap[0].startswith(nrip.split(";")[0]):
							if len(nrip.split(";")) > 1: 
								for subnet in nrip.split(";")[1].split(","):
									if nmap[0].startswith(nrip.split(";")[0]+subnet+'.'):
										routable = False
							else:
								routable = False

					if routable:
						while binging:
							time.sleep(0.5)

						binging = True

						if nmap[0] in "~".join(binged):
							self.output.put("[@] Bing>DNS\t: " + nmap[0] + "  -  pulling from cache...")
							for item in binged:
								if nmap[0] in item.split(":")[0]:
									hn = item.split(":")[1].split(";")									
									if len(hn) != 0 and hn[0] != "":
										hostnames = hn

									break
						else:
							self.opener.addheaders.append(('Cookie', 'SRCHHPGUSR=NRSLT=150'))

							self.output.put("[@] Bing>DNS\t: "+nmap[0])
							try: 
								bing_res = self.opener.open(("http://www.bing.com/search?q=ip%3a"+nmap[0])).read().split("sb_meta")
								for line in bing_res:
									res = re.findall( r".*<cite>(.*)</cite>.*", line )
									if res:
										hostnames.append(res[0].split('/')[0])

								binged.append(nmap[0] + ":" + ";".join(hostnames))
							except Exception, ex: 
								self.output.put("[x] Bing>DNS\t: Error - %s"%ex)
								hostnames = []

						binging = False

						# back to normal
						self.opener.addheaders = [('User-agent', useragent)]

						if len(hostnames) == 0: 
							self.output.put("[x] Bing>DNS\t: found no DNS entries for %s"%(nmap[0]))
						else:
							# remove any duplicates...
							seen = set()
							hostnames = [ x for x in hostnames if x not in seen and not seen.add(x)]
							self.output.put("[+] Bing>DNS\t: found %s DNS entries for %s" % (len(hostnames), nmap[0]))
							for hostname in hostnames[1:]:
								self.q.put("bing~" + nmap[0] + ", " + hostname + "|" + ", ".join(nmap[1:]))

							hostnames = [hostnames[0]]
					else:
						self.output.put("[-] %s is not a routable IP, skipping Bing>DNS for this host."%nmap[0])


				# Add the ip into the mix of hostnames
				if "bing~" in nmap[0]:
					hostnames = [nmap[1].split('|')[0]]
					nmap[0] = nmap[0].split('~')[1]
				else:
					for item in nmap[1].split('|'): 
						if item != "":
							hostnames.append(item)

					hostnames.append(nmap[0]) 

				for hostname in hostnames:
					if hostname != "":
						url = prefix+hostname + suffix
						if suffix == "":
							port = " [" + nmap[2] + "]"
						else:
							port = ""

						self.output.put("[>] Pulling\t: " + url + port)

						screenshot(url, hostname, nmap[2], "%s/images" % self.logdir, self.timestamp, self.scriptpath, self.pjs_path, self.logdir, self.output)

						try:
							data = self.opener.open(url)
							msg = "[+] Finished"
						except Exception, ex:
							if hasattr(ex, 'code'):
								e = ex.code
							elif hasattr(ex, 'reason'):
								e = ex.reason
							else:
								e = ex

							msg = "[x] Failed"
							# last ditch effort to try and snag the error info
							try:
								data = e
							except:
								pass

						parsedata(data, url + ', ' + ', '.join(nmap), self.opener, self.logdir, self.output, self.timestamp, self.scriptpath, self.getoptions, self.getrobots, self.defpass, self.crawl, url)
						self.output.put(msg+"\t: "+url+port)

				self.busy = False

				busy_count = 0
				for t in self.threads:
					if t.busy == True:
						busy_count += 1

				self.output.put(" [ Queue size [ %s ] - Threads Busy/Alive [ %s/%s ] ] "%(str(self.q.qsize()),busy_count,str(threading.active_count()-2)))
				self.q.task_done()


def screenshot(url, ip, port, destination, timestamp, scriptpath, pjs_path, logdir, output):
	filename = "%s/%s_%s_%s.png" % (destination, ip, timestamp, port)
	err='.'

	try:
		log_pipe = open("%s/rawr_%s.log" % (logdir, timestamp), 'ab')
		start = datetime.now()
		process = subprocess.Popen([pjs_path,"--web-security=no","--ignore-ssl-errors=yes","--ssl-protocol=any",scriptpath+"/data/screenshot.js", url, filename, useragent, str(ss_delay)], stdout=log_pipe, stderr=log_pipe)
		while process.poll() is None:
			time.sleep(0.1)
			now = datetime.now()
			if (now - start).seconds > timeout+1:
				sig = getattr(signal, 'SIGKILL', signal.SIGTERM)
				os.kill(process.pid, sig)
				os.waitpid(-1, os.WNOHANG)
				err=' - Timed Out.'
				break

		log_pipe.close()
		log_pipe = None
		process = None

		if os.path.exists(filename): 
			if os.stat(filename).st_size > 0:
				output.put('[>] Screenshot\t: [ %s ] >>\n   %s' % (url,filename))
			else:
				output.put('[X] Screenshot\t: [ %s ] Failed - 0 byte file. Deleted.' % (url))
				try:
					os.remove(filename)
				except:
					pass
		else:
			output.put('[X] Screenshot\t:  [ %s ] Failed%s' % (url,err))

	except Exception, ex:
		output.put('[!] Screenshot\t:  [ %s ] Failed - %s' % (url,ex))


def spider(origin, opener, logdir, timestamp, urls=None):
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
		for url_t2 in urls_t2:
			if d > 0: 
				coll.append((url_t1, url_t2))

			map_text.append( tabs + url_t2 )

			if len(url_t2.split("/")) > 2: 
				if spider_follow_subdomains == True:
					url_t2_hn = ".".join((url_t2.split("/")[2]).split(".")[-2:])
				else:
					url_t2_hn = url_t2.split("/")[2]

			if url_t2_hn in url_t1 and not url_t2 in urls_visited:
				urls_visited.append(url_t2)
				try:
					html = (opener.open(url_t2)).read().replace("\n","")
					urls_t3_r = list(set(re.findall(URL_REGEX, html, re.I)))
					urls_t3=[]
					for url_t3 in urls_t3_r:
						urls_t3.append(url_t3)

					if len(urls_t3) > 0 and d > 0:
						recurse(url_t2, urls_t3, d-1, tabs + "\t")					

				except Exception, ex:
					pass

	
	recurse(origin, urls, spider_depth, "\t")

	if len(coll) > 0:
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
		open('%s/maps/%s_%s.txt' % (logdir, fname, timestamp), 'w').write("\n".join(map_text))

def addtox(fname,val): 
	if fname.lower() in flist.lower():
		x[flist.lower().split(", ").index(fname.lower())] = re.sub('[\n\r,]', '', str(val))


def parsedata(data, nmap, opener, logdir, output, timestamp, scriptpath, getoptions, getrobots, defpass, crawl, full_url):
	x=[" "] * len(flist.split(","))

	def addtox(fname,val): 
		if fname.lower() in flist.lower():
			try:
				x[flist.lower().split(", ").index(fname.lower())] = re.sub('[\n\r,]', '', str(val))
			
			except Exception, ex:
				output.put("  -- Error placing %s in flist  --" % fname)

	addtox("url", nmap.split(", ")[0])
	addtox("host_ip", nmap.split(", ")[1])
	addtox("hostname", nmap.split(", ")[2])
	addtox("port", nmap.split(", ")[3])
	addtox("state", nmap.split(", ")[4])
	addtox("protocol", nmap.split(", ")[5])
	addtox("owner", nmap.split(", ")[6])
	addtox("service", nmap.split(", ")[7])
	addtox("rpc_info", nmap.split(", ")[8])
	if len(nmap.split(", ")) > 9:
		addtox("version", nmap.split(", ")[9])

	# identify country if possible
	#   * am considering loading this into memory with defpass
	if os.path.exists("%s/%s" % (scriptpath, IP_TO_COUNTRY)):
		ip = nmap.split(", ")[1].split('.')
		ipnum = (int(ip[0])*16777216) + (int(ip[1])*65536) + (int(ip[2])*256) + int(ip[3])
		for l in re.sub('[\"\r]', '', open("%s/%s" % (scriptpath, IP_TO_COUNTRY)).read()).split('\n'):
			try:
				if l != "" and (not "#" in l) and (int(l.split(',')[1]) > ipnum > int(l.split(',')[0])):
					addtox("country", "[%s]-%s" % (l.split(',')[4],l.split(',')[6]))
					break

			except Exception, ex:
				output.put("  -- Error parsing %s:  %s  --" % (ex, IP_TO_COUNTRY))

	if getoptions:
		try:
			req = urllib2.Request(url=nmap.split(", ")[0])
			req.get_method = lambda : "OPTIONS"
			resp = opener.open(req)
			options = resp.info().getheaders('Allow')[0].replace(',','|')
			addtox("allow", options)
		except Exception:
			pass

		resp = None

	if getrobots:
		try:
			host = nmap.split(", ")[0].split(":")[1].replace("//",'')
			dat = opener.open("%s/robots.txt" % nmap.split(", ")[0])
			dat_content = dat.read()
			if dat.getcode() == 200 and "llow:" in dat_content: 
				if not os.path.exists("robots"): os.makedirs("robots")
				open("./robots/%s_robots.txt" % host, 'w').write(dat_content)
				output.put("   [r] Pulled robots.txt:  ./robots/%s_%s_robots.txt  " % (host,nmap.split(", ")[3]))
				addtox("robots.txt", "y")

			dat = None
		except Exception:
			pass

	# grab cookies
	if hasattr(data, 'info'):
		cookies = data.info().getheaders('Set-Cookie')
		if cookies and (len(cookies) > 0): 	
			try:
				os.mkdir("cookies")
			except:
				pass

			cout = ""
			for cookie in cookies:
				cout += cookie+'\n\n'

			open("./cookies/%s_%s.txt"%(nmap.split(", ")[0].split('/')[2].split(':')[0],nmap.split(", ")[3]),'w').write(cout)
			addtox("cookies", len(cookies))

	try:		
		server_type = ""
		html = data.read()
		addtox("endurl", data.geturl())
		addtox("returncode", "[%s]" % str(data.getcode()))
		for field in data.info().__str__().split("\r\n"):
			if field != "":
				fname = field.split(": ")[0]
				fval = re.sub('[\n\r]', '', field.split(": ")[1])
				fval = fval.replace(",",'')
				if "server" in fname.lower():
					server_type=fval.lower()

				addtox(fname.lower(), fval)

		addtox("info", (re.sub('[\n\r,]', '', data.info().__str__())))
	except: 
		html = str(data)

	if "urlopen error [Errno" in html:
		line = "%s%s" % (nmap,', '.join(x))
	else:
		addtox("title", ' : '.join(re.findall("""<title.*?>([^<]+)<\/title>""", html, re.I)))

		meta = re.findall("""<meta[^>^=]+content[\s]*=[\s]*['"]([^"^'^>]+)['"][^>^=]+name[\s]*=[\s]*['"]?(.*)['"]?""", html, re.I)
		meta += re.findall("""<meta[^>^=]+name[\s]*=[\s]*['"]?(.*)['"]?[^>^=]+content[\s]*=[\s]*['"]?([^"^'^>]+)['"]?""", html, re.I)
		m = ""
		for field in meta:
			if field != "":
				fname = field[0].strip('"')   
				fval = re.sub('[\n\r,]', '', field[1])
				m += "%s:%s, " % (fname, fval)
				addtox(fname.lower(), fval)

		addtox("meta", m.replace(",",'; '))
		urls = []
		for url in re.findall(URL_REGEX, html, re.I):
			urls.append(url.split("<")[0])

		addtox("urls", ';'.join(urls) )

		# Spidering out
		if crawl == True and foundgv == True:
			output.put("[+] Spidering\t: %s" % full_url)
			spider(nmap.split(", ")[0], opener, logdir, timestamp, urls)

		# Run through our user-defined content modules.
		#  *** If a field isn't present in 'flist' (in the settings section), it won't be added at this time.
		for field,regxp,modtype,scope in modules:
			# MODTYPE_CONTENT - returns all matches, seperates by ';'
			if modtype == 0:	
				addtox(field, ';'.join(re.findall(regxp, html, re.I)) )

			# MODTYPE_TRUEFALSE - returns 'True' or 'False' based on regxp
			elif modtype == 1:
				if len(re.findall(regxp, html, re.I)) > 0:
					addtox(field, "True")
				else:
					addtox(field, "False")

			# MODTYPE_COUNT - counts the number of returned matches
			elif modtype == 2:
				addtox(field, len(re.findall(regxp, html, re.I)) )

			else:
				output.put("**  skipping %s - \"\"\"%s\"\"\"... invalid modtype" % (field, regxp) )


	#looking for SSL data
	if any(s in nmap.split(", ")[7].lower() for s in ["https","ssl"]):
		ssl_data = ""
		for xmlfile in glob("*.nessus") + glob("*.xml"):
			try:
				if "<NessusClientData_v2>" in open(xmlfile).read():
					for node in minidom.parse(xmlfile).getElementsByTagName('ReportHost'): 
						for item in node.getElementsByTagName('ReportItem'):
							service = item.getAttribute('svc_name')
							plugin = item.getAttribute('pluginName')
							if (service == "www") and (plugin == "SSL Certificate Information"):
								#SSL stuff  ..  ;)
								pass
								#nmapout += ", ".join([ip,hostname,portnum,state,protocol,owner,service,sunrpc_info,version_info])+", \n"
								#count += 1

								if (nmap.split(", ")[1] in hostnames) or (match == True):
									#we're on the correct report item - placeholder here until i can get the format
									output.put("......Found SSL data for %s....." % nmap.split(', ')[1])
									#addtox("SSL_Tunnel-Weakest", weakest.strip())
									#addtox("SSL_Tunnel-Ciphers", ciphers.strip("; "))
									#addtox("SSL_Tunnel-CiphersRaw", c_data.replace("\n",";"))
									#ssl_data = script.getAttribute('output')

								break; break

				else:
					# nmap xml output
					dom = minidom.parse(xmlfile).getElementsByTagName('nmaprun')[0]
					for node in dom.getElementsByTagName('host'): 
						h = ""		
						for n in node.getElementsByTagName('hostname'):
							h += n.getAttribute('name')

						for n in node.getElementsByTagName('address'):
							h += n.getAttribute('addr')
			
						match = False
						for hostname in nmap.split(", ")[2].split('|'):
							if hostname in h:
								match == True
								break

						if (nmap.split(", ")[1] in h) or (match == True):
							for port in node.getElementsByTagName('port'):
								if port.getAttribute('portid') == nmap.split(", ")[3]: 
									for script in port.getElementsByTagName('script'):
										if script.getAttribute('id') == "ssl-enum-ciphers":
											ciphers = ""
											c_data = script.getAttribute('output')
											addtox("SSL_Tunnel-CiphersRaw", c_data.replace("\n",";"))
											c_data = c_data.split('NULL\n  ')
											for v in c_data[0:-1]:
												ciphers+= v.strip('\n').strip().split('\n')[0]+"; "

											addtox("SSL_Tunnel-Ciphers", ciphers.strip("; "))
											weakest = c_data[-1].strip('\n').strip().split('=')
											if len(weakest) > 1:
												weakest = weakest[1]
											else:
												weakest = weakest[0]

											addtox("SSL_Tunnel-Weakest", weakest.strip())

										if script.getAttribute('id') == "ssl-cert":
											ssl_data = script.getAttribute('output')

									break; break

				try:
					dom.unlink()
				except:
					pass

			except Exception, ex:
				output.put("\n\n  !! Unable to parse %s  !!\n\t\t Error: %s\n\n" % (xmlfile, ex))

		if ssl_data != "":
			# write the cert to a file
			if not os.path.exists("ssl_certs"):
				os.mkdir("ssl_certs") 

			open("./ssl_certs/%s.cert" % (nmap.split(", ")[1]),'w').write(ssl_data)
			addtox("SSL_Cert-Raw", ssl_data)

			for line in ssl_data.split('\n'):
				if "issuer" in line.lower():
					addtox("SSL_Cert-Issuer", line.split(": ")[1])

				elif "subject" in line.lower():
					addtox("SSL_Cert-Subject", line.split(": ")[1])

					if "*" in line.split(": ")[1]:
						subject = line.split(": ")[1].split("*")[1]

					else:
						subject = line.split(": ")[1]

					if subject in nmap.split(', ')[0:3]: 
						addtox("SSL_Cert-Verified", "yes")

				elif "md5" in line.lower():
					addtox("SSL_Cert-MD5", line.split(": ")[1].replace(" ",''))

				elif "sha1" in line.lower():
					addtox("SSL_Cert-SHA-1", line.split(": ")[1].replace(" ",''))

				elif "algorithm" in line.lower():
					addtox("SSL_Cert-KeyAlg", "%s%s"%line.split(": ")[1] )
					# need to take another look at this one.  no seeing it atm

				elif "not valid before" in line:
					notbefore = line.split(": ")[1].strip()
					addtox("SSL_Cert-notbefore", notafter)

				elif "not valid after" in line:
					notafter = line.split(": ")[1].strip()
					addtox("SSL_Cert-notafter", notafter)

				try:
					notbefore = datetime.strptime(notbefore, '%Y-%m-%d %H:%M:%S')
					notafter = datetime.strptime(notafter, '%Y-%m-%d %H:%M:%S')
					vdays = ( notafter - notbefore ).days
					if datetime.now() > notafter: 
						daysleft = "EXPIRED"

					else: 
						daysleft = ( notafter - datetime.now() ).days

				except Exception:
					# some certificates have non-standard dates in these fields.  
					vdays = "unk"
					daysleft = "unk"

				addtox("SSL_Cert-ValidityPeriod", vdays)
				addtox("SSL_Cert-DaysLeft", daysleft)

	# check title, service, and server fields for matches in defpass file
	if defpass:
		defpwd = ""
		services_txt = ",".join(nmap.split(',')[6:]).lower() + ",%s"%server_type
		for pdef in defpass:
			try:
				if not pdef.startswith("#"):
					if (pdef.split(',')[0].lower() in (services_txt) ): 
						defpwd += "%s;" % (':'.join(pdef.split(',')[0:5]))
			except Exception, ex:
				output.put(" -- Error parsing %s: %s --" % (ex, DEFPASS_FILE))

		if defpwd: 
			addtox("Default Password Suggestions", defpwd.strip(";"))

	try:
		xdata = str(','.join(x))
		nmap = str(nmap)
	except Exception, ex:
		output.put("\t\t!!  Error - " % ex)
		output.put(x)
		xdata = ""

	open('index_%s.html' % timestamp, 'a').write("%s%s<br>" % (nmap, xdata))
	open("rawr_%s_serverinfo.csv" % timestamp, 'a').write("\n%s" % (xdata))


def write_to_csv(timestamp, ip, hostname, portnum, state, protocol, owner, service, sunrpc_info, version_info):
	x=[" "] * len(flist.split(","))

	if not os.path.exists("rawr_%s_serverinfo.csv" % timestamp):
		open("rawr_%s_serverinfo.csv" % timestamp, 'w').write(flist)

	addtox("host_ip", ip)
	addtox("hostname", hostname)
	addtox("port", portnum)
	addtox("state", state)
	addtox("protocol", protocol)
	addtox("owner", owner)
	addtox("service", service)
	addtox("rpc_info", sunrpc_info)
	addtox("version", version_info)		

	try:
		open("rawr_%s_serverinfo.csv" % timestamp, 'a').write("\n%s" % (str(','.join(x))))
	except Exception, ex:
		print "\t\t    [!] Unable to write .csv !\n\t\t Error: %s\n\n" % ex
		print x


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
		ver_data = urllib2.urlopen(url).read()
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
				data = urllib2.urlopen(url).read()
				open("rawr_" + script_ver + ".tar", 'w+b').write( urllib2.urlopen(url).read() )
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
					open(fname,'w+b').write( urllib2.urlopen(url).read() )

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
			open("data/defpass_tmp.csv",'w').write( urllib2.urlopen(url).read() )
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
			open(IP_TO_COUNTRY + ".tar.gz",'w+b').write( urllib2.urlopen(url).read() )
			tarfile.open(IP_TO_COUNTRY + ".tar.gz").extractall('./data')
			os.remove(IP_TO_COUNTRY + ".tar.gz")
			print "     ++ Success ++\n"

		except Exception, ex:
			print "     !! Failed:  %s\n" % ex
			sys.exit(1)
	else:
		print "\n     -- NOT updating %s - already at ver.%s\n" % (IP_TO_COUNTRY, ip2c_ver)

	print "  ++  Update Complete  ++\n\n"


def inpath(app):
	for path in os.environ["PATH"].split(os.pathsep):
		exe_file = os.path.join(path, app)
		if os.path.isfile(exe_file) and os.access(exe_file, os.X_OK):
			return exe_file


def writelog(msg, logfile):
	print msg
	open(logfile, 'a').write(msg + "\n")

