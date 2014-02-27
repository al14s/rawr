import os
import sys
import shutil
import tarfile
import platform
import subprocess
import signal
import re
import time
import threading
import sqlite3
import traceback
import Image
import colorsys
import socket
from urlparse import urlparse
from datetime import datetime
from Queue import Queue

# Not in stdlib, but included in lib folder
sys.path.append('./lib/')
import requests
from lxml import html, etree
from constants import *
from conf.modules import *
from conf.settings import useragent, flist, timeout, ss_delay, spider_depth,\
    spider_follow_subdomains, spider_url_limit, spider_timeout, nthreads

binged = {}
binging = False

threads = []
q = Queue()  # The main queue.  Holds initial host data.
output = Queue()  # The output queue - prevents output overlap


class out_thread(threading.Thread):  # Worker class that displays msgs in the 'output' queue in order and one at a time.
    def __init__(self, queue, logfile, opts):
        threading.Thread.__init__(self)
        self.queue = queue
        self.logfile = logfile
        self.opts = opts
        global writelog

    def run(self):
        while True:
            writelog(self.queue.get(), self.logfile, self.opts)
            self.queue.task_done()


class sithread(threading.Thread):  # Threading class that enumerates hosts contained in the 'q' queue.
    def __init__(self, timestamp, scriptpath, pjs_path, logdir, output, opts):
        threading.Thread.__init__(self)        
        self.timestamp = timestamp
        self.scriptpath = scriptpath
        self.pjs_path = pjs_path
        self.logdir = logdir
        self.output = output
        self.opts = opts
        self.terminate = False
        self.busy = False

    def run(self):

        global binged
        global binging
        global q
        global nthreads

        try:
            while not self.terminate:
                time.sleep(0.5)

                if not q.empty():
                    self.busy = True
                    target = q.get()
                    hostname = ''
                    port = ''

                    try:
                        prefix = "http://"
                        if target['service_name'] == "https":
                            prefix = "https://"

                        if not target['port'] in ["80", "443"]:
                            port = ":" + target['port']

                        if self.opts.bing_dns and (not 'is_bing_result' in target.keys()):
                            # Don't do Bing>DNS lookups for non-routable IPs
                            routable = True
                            nrips = ["10.", "172.", "192.168.", "127.16-31", "169."]
                            for nrip in nrips:
                                if "-" in nrip:
                                    a = int(nrip.split(".")[1].split("-")[0])
                                    while not a <= int(nrip.split(".")[1].split("-")[1]):
                                        if target['ipv4'].startswith('.'.join([nrip.split('.')[0], str(a)])):
                                            routable = False
                                        a += 1

                                elif target['ipv4'].startswith(nrip):
                                    routable = False

                            if routable:
                                if target['ipv4'] in binged.keys():
                                    if target['port'] in binged[target['ipv4']][1]:
                                        self.output.put("  [.] Bing>DNS\t: " + target['ipv4'] + " (" +
                                                        target['hostnames'][0] + ") - duplicate, skipping...")

                                    else:
                                        binged[target['ipv4']][1].append(target['port'])
                                        self.output.put("  [.] Bing>DNS\t: " + target['ipv4'] + " (" +
                                                        target['hostnames'][0] + ") - pulling from cache...")
                                        target['hostnames'] = binged[target['ipv4']][0]

                                else:
                                    while binging:  # The intention here is to avoid flooding Bing with requests.
                                        time.sleep(0.5)

                                    binging = True
                                    self.output.put("  [@] Bing>DNS\t: " + target['ipv4'])
                                    cookies = dict(SRCHHPGUSR='NRSLT=150')

                                    try:
                                        bing_res = requests.get("http://www.bing.com/search?q=ip%3a" + target['ipv4'],
                                                                cookies=cookies).text.split("sb_meta")

                                    except Exception:
                                        error = traceback.format_exc().splitlines()
                                        error_msg("\n".join(error))
                                        self.output.put("  [x] Bing>DNS:\n\t%s\n" % "\n\t".join(error))
                                        bing_res = ""

                                    hostnames = []
                                    for line in bing_res:
                                        res = re.findall(r"<cite>(.*?)</cite>", line)
                                        if res:
                                            res = res[0].replace("https", '').replace("http", '').replace("://", '').split('/')[0]
                                            if res != '':
                                                hostnames.append(res)

                                    if len(hostnames) > 0:
                                        # remove any duplicates from our list of domains...
                                        hostnames = list(set(hostnames))
                                        self.output.put("  [+] Bing>DNS\t: found %s DNS names for %s" % (len(hostnames), target['ipv4']))

                                        # distribute the load
                                        for hostname in hostnames:
                                            if not hostname.strip(': ') in [target['ipv4'], "https", "http", '']:
                                                new_target = target.copy()
                                                new_target['is_bing_result'] = True
                                                new_target['hostnames'] = [hostname.strip()]
                                                self.output.put("  [+] Bing>DNS\t: [ %s ] injected into queue." % (new_target['hostnames'][0]))
                                                q.put(new_target)

                                    else:
                                        self.output.put("  [x] Bing>DNS\t: found no DNS entries for %s" % (target['ipv4']))

                                    binged[target['ipv4']] = [hostnames, [target['port']]]

                                    binging = False

                            else:
                                self.output.put("  [-] %s is not routable. Skipping Bing>DNS for this host." %
                                                target['ipv4'])

                        if len(target['hostnames']) > 1:
                            # distribute the load
                            for hostname in target['hostnames'][1:]:
                                new_target = target.copy()
                                new_target['hostnames'] = [hostname.strip()]
                                q.put(new_target)
                                self.output.put("  [+] Off-loaded %s:%s to the queue. [ %s%s ]" %
                                                (new_target['hostnames'][0],
                                                 new_target['port'],
                                                 target['ipv4'], port))

                        if len(target['hostnames']) > 0:
                            hostname = target['hostnames'][0]

                            target['url'] = prefix + hostname + port
                            self.output.put("  [>] Pulling\t: " + hostname + port)

                            try:
                                target['res'] = requests.get(target['url'], headers={"user-agent": useragent}, verify=False,
                                                             timeout=timeout, allow_redirects=False,
                                                             proxies=self.opts.proxy_dict)

                                msg = ["  [+] Finished", ""]

                            except requests.ConnectionError:
                                if target['res'].status_code == 401:
                                    open("./auth_fail.log", 'w').write(target['url'])

                                msg = ["  [x] Not found", ""]

                            except socket.timeout:
                                msg = ["  [x] Timed out", ""]

                            except Exception:
                                error = traceback.format_exc().splitlines()
                                error_msg("\n".join(error))
                                msg = ["  [x] Error ", ":\n\t%s\n" % "\n\t".join(error)]

                            if self.opts.getoptions and 'res' in target.keys():
                                try:
                                    res = (requests.options(target['url'], headers={"user-agent": useragent}, verify=False,
                                                            timeout=timeout, allow_redirects=False,
                                                            proxies=self.opts.proxy_dict))

                                    if 'allow' in res.headers:
                                        target['options'] = res.headers['allow'].replace(",", " | ")

                                    self.output.put("      [o] Pulled OPTIONS : [ %s ]" % target['url'])

                                except requests.ConnectionError:
                                    msg = ["  [x] Not found", ""]

                                except socket.timeout:
                                    self.output.put("      [x] Timed out pulling OPTIONS: [ %s ]" % target['url'])

                                except Exception:
                                    error = traceback.format_exc().splitlines()
                                    error_msg("\n".join(error))
                                    self.output.put("      [x] Failed pulling OPTIONS: [ %s ]\n\t%s\n" % (target['url'],
                                                                                                          "\n\t".join(error)))
                            target['hist'] = 256
                            if not self.opts.noss and 'res' in target.keys():
                                target['hist'] = screenshot(target, self.logdir, self.timestamp, self.scriptpath,
                                                            self.opts.proxy_dict, self.pjs_path, self.output)

                            if self.opts.getcrossdomain and 'res' in target.keys():
                                try:
                                    res = requests.get("%s/crossdomain.xml" % target['url'], verify=False,
                                                       timeout=timeout, allow_redirects=False, proxies=self.opts.proxy_dict)
                                    if res.status_code == 200:
                                        if not self.opts.json_min:
                                            if not os.path.exists("cross_domain"):
                                                try:
                                                    os.makedirs("cross_domain")

                                                except:
                                                    pass

                                            try:
                                                v = str(res.text)

                                            except UnicodeEncodeError:
                                                v = unicode(res.text).encode('unicode_escape')

                                            open("./cross_domain/%s_%s_crossdomain.xml" %
                                                 (hostname, target['port']), 'w').write(v)
                                            self.output.put("      [c] Pulled crossdomain.xml:" +
                                                            "./cross_domain/%s_%s_crossdomain.xml  " %
                                                            (hostname, target['port']))
                                        target['crossdomain'] = "y"

                                except requests.ConnectionError:
                                    msg = ["  [x] Not found", ""]

                                except socket.timeout:
                                    self.output.put("      [x] Timed out pulling crossdomain.xml: [ %s%s ]" %
                                                    (hostname, port))

                                except Exception:
                                    error = traceback.format_exc().splitlines()
                                    error_msg("\n".join(error))
                                    self.output.put("      [x] Failed pulling crossdomain.xml:\n\t%s\n" %
                                                    "\n\t".join(error))

                            if self.opts.getrobots and 'res' in target.keys():
                                try:
                                    res = requests.get("%s/robots.txt" % target['url'], verify=False,
                                                       timeout=timeout, allow_redirects=False, proxies=self.opts.proxy_dict)
                                    if res.status_code == 200 and "llow:" in res.text:
                                        if not self.opts.json_min:
                                            if not os.path.exists("robots"):
                                                try:
                                                    os.makedirs("robots")

                                                except:
                                                    pass

                                            try:
                                                v = str(res.text)

                                            except UnicodeEncodeError:
                                                v = unicode(res.text).encode('unicode_escape')

                                            open("./robots/%s_%s_robots.txt" % (hostname, target['port']), 'w').write(v)
                                            self.output.put("      [r] Pulled robots.txt:  ./robots/%s_%s_robots.txt  " %
                                                            (hostname, target['port']))
                                        target['robots'] = "y"

                                except requests.ConnectionError:
                                    msg = ["  [x] Not found", ""]

                                except socket.timeout:
                                    self.output.put("      [x] Timed out pulling robots.txt: [ %s%s ]" % (hostname, port))

                                except Exception:
                                    error = traceback.format_exc().splitlines()
                                    error_msg("\n".join(error))
                                    self.output.put("      [x] Failed pulling robots.txt:\n\t%s\n" % "\n\t".join(error))

                            if self.opts.crawl and not self.opts.json_min and 'res' in target.keys():
                                if not os.path.exists("maps"):
                                    try:
                                        os.makedirs("maps")

                                    except:
                                        pass

                                crawl(target, self.logdir, self.timestamp, self.opts)

                            parsedata(target, self.logdir, self.timestamp, self.scriptpath, self.opts)
                            self.output.put("%s  [ %s%s ]%s" % (msg[0], hostname, port, msg[1]))

                    except Exception:
                        error = traceback.format_exc().splitlines()
                        error_msg("\n".join(error))
                        self.output.put("  [x] Failed : [ %s%s ]\n\t%s\n" % (hostname, port, "\n\t".join(error) ))

                    self.busy = False

                    busy_count = 0
                    for t in threads:
                        if t.busy:
                            busy_count += 1

                    self.output.put("  [i] Main queue size [ %s ] - Threads Busy/Total [ %s/%s ]" % (str(q.qsize()),
                                                                                                     busy_count, nthreads))

                    q.task_done()

        except KeyboardInterrupt:
            pass


def screenshot(target, logdir, timestamp, scriptpath, proxy, pjs_path, o):
    filename = "%s/%s_%s_%s.png" % ("%s/images" % logdir, target['url'].split("/")[2].split(":")[0],
                                    timestamp, target['port'])
    err = '.'

    try:
        with open("%s/rawr_%s.log" % (logdir, timestamp), 'ab') as log_pipe:
            start = datetime.now()
            cmd = [pjs_path]

            if proxy:
                cmd.append("--proxy=%s" % proxy['http'])  # Here, the same ip:port is used for both http and https.

            cmd += "--web-security=no", "--ignore-ssl-errors=yes", "--ssl-protocol=any",\
                   (scriptpath + "/data/screenshot.js"), target['url'], filename, useragent, str(ss_delay)

            process = subprocess.Popen(cmd, stdout=log_pipe, stderr=log_pipe)

            while process.poll() is None:
                time.sleep(0.1)
                now = datetime.now()
                if (now - start).seconds > timeout + 1:
                    try:
                        sig = getattr(signal, 'SIGKILL', signal.SIGTERM)
                        os.kill(process.pid, sig)
                        os.waitpid(-1, os.WNOHANG)
                        err = ' Timed Out.'

                    except:
                        pass

                    break

        if os.path.exists(filename): 
            if os.stat(filename).st_size > 0:
                o.put('      [+] Screenshot :     [ %s ]' % target['url'])

                try:  # histogram time!
                    r, g, b = 0, 0, 0
                    c = 0
                    img = Image.open(filename).resize((150, 150))
                    for x in xrange(img.size[0]):
                        for y in xrange(img.size[1]):
                            t = img.load()[x, y]
                            r += t[0]
                            g += t[1]
                            b += t[2]
                            c += 1

                    hsv = colorsys.rgb_to_hsv((r/c), (g/c), (b/c))
                    return str(hsv[2])

                except:
                    return 0

            else:
                o.put('      [X] Screenshot :     [ %s ] Failed - 0 byte file. Deleted.' % target['url'])
                try:
                    os.remove(filename)
                    shutil.copyfile(scriptpath + "/data/error.png", "%s/images/error.png" % logdir)

                except:
                    pass
        else:
            o.put('      [X] Screenshot :     [ %s ] Failed - %s' % (target['url'], err))
            shutil.copyfile(scriptpath + "/data/error.png", "%s/images/error.png" % logdir)

    except:
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        o.put("      [!] Screenshot :     [ %s ] Failed\n\t%s\n" % (target['url'], "\n\t".join(error) ))


def crawl(target, logdir, timestamp, opts):  # Our Spidering function.
    output.put("      [>] Spidering  :     [ %s ]" % target['url'])
    target['docs'] = []

    def recurse(url_t1, urls_t2, tabs, depth=0):
        if opts.verbose:
            output.put("      [i] depth %s - time %d - urls %s" % (depth, (datetime.now() - time_start).total_seconds(),
                                                                   len(list(set(urls_visited))) ))
        
        url_t1 = url_t1.replace(":", "-")  # supplement regx

        for url_t2 in urls_t2:
            if depth > spider_depth:
                break

            elif len(list(set(urls_visited))) > spider_url_limit:
                if opts.verbose:
                    output.put("      [!] Spidering stopped :   [ %s ] - URL limit reached" % target['url'])
                break

            elif (datetime.now() - time_start).total_seconds() > spider_timeout:
                if opts.verbose:
                    output.put("      [!] Spidering stopped :   [ %s ] - Timed out" % target['url'])
                break

            if not url_t2 in ("https://ssl", "http://www", "http://", "http://-", "http:", "https:"):  # ga junk
                coll.append((url_t1, url_t2.replace(":", "-")))

                open('%s/maps/links_%s_%s__%s.txt' %
                     (logdir, hname, target['port'], timestamp), 'a').write(tabs + url_t2 + "\n")

                if not url_t2 in urls_visited:
                    urls_visited.append(url_t2)
                    p = urlparse(url_t2)

                    if p.path.split(".")[-1].lower() in FILE_TYPES and url_t2 not in target['docs']:
                        output.put("          [+] File found  - %s" % url_t2)
                        target['docs'].append(str(url_t2))

                        open('%s/maps/docs_%s_%s__%s.txt' %
                             (logdir, hname, target['port'], timestamp), 'a').write(url_t2 + "\n")

                    elif len(url_t2.split("/")) > 2:
                        if spider_follow_subdomains:
                            url_t2_hn = ".".join((url_t2.split("/")[2]).split(".")[-2:])

                        else:
                            url_t2_hn = url_t2.split("/")[2]

                        if url_t2_hn in url_t1:
                            try:
                                d = requests.get(url_t2, headers={"user-agent": useragent, "referer": url_t1},
                                                 verify=False, timeout=timeout, allow_redirects=False,
                                                 proxies=opts.proxy_dict).text.replace("\n", "")

                                urls_t3 = []
                                for u in list(set(re.findall(URL_REGEX, d, re.I))):
                                    urls_t3.append(u.split('"')[0].split("'")[0].split(
                                                   "<")[0].split("--")[0].rstrip('%)/.'))  # supplement the regex

                                try:  # parse the html for tags w/ href or source
                                    cxt = html.fromstring(d)
                                    for el in cxt.iter():
                                        if el.tag in ['link', 'a', 'script', 'iframe',
                                                      'applet', 'object', 'embed', 'form']:
                                            for i, v in el.items():
                                                if i in ("src", "href"):
                                                    if "mailto" in v:
                                                        try:
                                                            if not v.split(":")[1] in target['email_addresses']:
                                                                target['email_addresses'].append(v.split(":")[1])

                                                        except:
                                                            target['email_addresses'] = [v.split(":")[1]]

                                                    else:
                                                        if not "//" in v:  # a relative link
                                                            v = v.replace("../",'')
                                                            if not v.startswith("/"):
                                                                v = "/" + v

                                                            v = p.scheme + "://" + p.netloc + v

                                                        urls_t3.append(v)

                                except:
                                    pass

                                urls_t3 = list(set(urls_t3))
                                if len(urls_t3) > 0:
                                    if not (len(list(set(urls_visited))) > spider_url_limit or depth > spider_depth or
                                       (datetime.now() - time_start).total_seconds() > spider_timeout):
                                        recurse(url_t2, urls_t3, tabs + "\t", depth + 1)

                            except Exception:
                                pass

    coll = []
    urls_visited = []
    hname = target['url'].split("/")[2]
    time_start = datetime.now()
    recurse(target['url'], [target['url']], "\t")
    target['doc_count'] = len(target['docs'])

    if len(coll) > 1:
        try: 
            import pygraphviz as pgv

            output.put("      [+] Finished spider: [ %s ] - building graph..." % target['url'])

            # Graph creation
            gr = pgv.AGraph(splines='ortho', rankdir='LR')    # need to catch any exceptions this thing throws!!
            gr.node_attr['shape'] = 'rect'

            c = []
            # Add nodes and edges
            for item in coll:
                c.append(item[0].strip('"/\; ()'))  # Stripping these actually fixes the previous errors
                c.append(item[1].strip('"/\; ()'))  # Not a permanent fix, but will do for now!

            for node in list(set(c)):
                if node == target['url']:
                    gr.add_node(node, root=True)

                else:
                    gr.add_node(node)

            for item in coll:
                if not item[0] == item[1]:
                    try:
                        gr.add_edge((item[0].strip('"/\; ()'), item[1].strip('"/\; ()')))

                    except Exception:
                        pass

            # Draw as PNG
            gr.layout(prog='dot')
            # will get a warning if the graph is too large - not fatal
            gr.draw('%s/maps/diagram_%s_%s__%s.png' % (logdir, urlparse(target['url']).netloc, target['port'], timestamp) )
            target['diagram'] = "X"

        except Exception:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            output.put("\n    [!] Unable to create site chart: [ %s ]\n\t%s\n" % (target['url'], "\n\t".join(error) ))


def parsedata(target, logdir, timestamp, scriptpath, opts):  # Takes raw site response and parses it.
    global modules

    x=[" "] * len(flist.split(","))

    for i,v in target.items():
        target[i] = target[str(i)]

    # identify country if possible
    if os.path.exists("%s/%s" % (scriptpath, IP_TO_COUNTRY)):
        ip = target['ipv4'].split('.')
        ipnum = (int(ip[0])*16777216) + (int(ip[1])*65536) + (int(ip[2])*256) + int(ip[3])
        for l in re.sub('[\"\r]', '', open("%s/%s" % (scriptpath, IP_TO_COUNTRY)).read()).split('\n'):
            try:
                if l != "" and (not "#" in l) and (int(l.split(',')[1]) > ipnum > int(l.split(',')[0])):
                    target['country'] = "[%s]-%s" % (l.split(',')[4], l.split(',')[6])
                    break

            except Exception:
                error = traceback.format_exc().splitlines()
                error_msg("\n".join(error))
                output.put("  [!] IPtoCountry parse error:\n\t%s\n" % "\n\t".join(error))

    if 'res' in target.keys():
        # eat cookie now....omnomnom
        if len(target['res'].cookies) > 0:    
            try:
                os.mkdir("cookies")

            except:
                pass

            open("./cookies/%s_%s.txt" %
                 (target['url'].split("/")[2].split(":")[0], target['port']), 'w').write(str(target['res'].cookies))
            target['cookies'] = len(target['res'].cookies)

            d = target['res'].cookies
            if 'Content-Type' in target.keys():
                d += target['res'].headers['Content-Type']

            target['charset'] = re.findall("charset=(.*)[\s|\r]", str(d))

        target['endurl'] = target['res'].url

        if "server" in target['res'].headers:
            target['server'] = target['res'].headers['server']

        target['encoding'] = target['res'].encoding

        hist = []
        for h in target['res'].history:
            hist.append(h.url)

        if len(hist) > 0: 
            target['history'] = hist

        target['returncode'] = str(target['res'].status_code)

        target['urls'] = []

        # quicker and not bound to specific elements/attributes
        for url in re.findall(URL_REGEX, target['res'].text, re.I):
            target['urls'].append(url.split("'")[0].rstrip(')/.'))

        # Run through any user-defined regex filters.
        #  *** If a field isn't present in 'flist' (in the settings section), it won't be added at this time.
        parsermods = []
        for field, regxp, modtype in modules:
            try:
                # MODTYPE_CONTENT - returns all matches, seperates by ';'
                if modtype == 0:    
                    for i in (re.findall(regxp, target['res'].text, re.I)):
                        if not field in target.keys():
                            target[field] = []

                        target[field].append(str(i))

                # MODTYPE_TRUEFALSE - returns 'True' or 'False' based on regxp
                elif modtype == 1:
                    if len(re.findall(regxp, target['res'].text, re.I)) > 0:
                        target[field] = "True"

                    else:
                        target[field] = "False"

                # MODTYPE_COUNT - counts the number of returned matches
                elif modtype == 2:
                    target[field] = len(re.findall(regxp, target['res'].text, re.I))

                # PARSER modules
                elif modtype in [3, 4, 5]:
                    if type(regxp) == tuple and len(regxp) == 3:
                        parsermods.append((field, regxp, modtype))

                else:
                    output.put("  [!] skipping %s - invalid modtype" % (field))

            except Exception:
                error = traceback.format_exc().splitlines()
                error_msg("\n".join(error))
                output.put("  [!] skipping module '%s' :\n\t%s\n" % (field, "\n\t".join(error)) )

        # parse the html for different element types
        try:
            cxt = html.fromstring(target['res'].content)
            for el in cxt.iter():
                items = el.items()
                tag = el.tag

                # user-defined modules
                for mod in [m for m in parsermods if str(m[1][0]).lower() == str(tag).lower()]:
                    # mods that reference the current element tag
                    val = ""
                    try:
                        if "text" in mod[1][1] and el.text is None:
                            val = el.text

                        val += " %s" % (" ".join([v for i, v in items if i in mod[1][1]]))
                        #  [!] skipping module 'jquery_tf':
                        #      File "/home/axbyers/Desktop/rawr/lib/functions.py", line 521, in parsedata
                        #        val += " %s" % (" ".join([v for i, v in items if i in mod[1][1]]))
                        #    TypeError: unsupported operand type(s) for +=: 'NoneType' and 'str'

                        if val != "":
                            r = (re.findall(mod[1][2], val, re.I))

                            if mod[2] == 3:
                                for i in r:
                                    if not mod[0] in target.keys():
                                        target[mod[0]] = []

                                    target[mod[0]].append(i)

                            elif mod[2] == 4:
                                if len(r) > 0:
                                    target[mod[0]] = ["True"]
                                else:
                                    target[mod[0]] = ["False"]

                            elif mod[2] == 5:
                                target[mod[0]] = [len(r)]

                            else:
                                raise("invalid modtype - %s" % mod[2])

                    except Exception:
                        error = traceback.format_exc().splitlines()
                        error_msg("\n".join(error))
                        output.put("  [!] skipping module '%s':\n\t%s\n" % (mod[0], "\n\t".join(error)))

                # some default checks
                if tag == "meta":
                    for i,v in items:
                        if i == "name":
                            target[v] = el.text

                elif tag == "title":
                    target['title'] = el.text

                elif tag == "script":
                    for i, v in items:
                        if i == "src":
                            if not 'file_includes' in target.keys():
                                target['file_includes'] = []

                            target['file_includes'].append(v)

                    target['script'] = len(items)

                elif tag in ['link', 'a']:
                    for i, v in items:
                        if i == "href":
                            if "mailto:" in v:
                                if not 'email_addresses' in target.keys():
                                    target['email_addresses'] = []

                                target['email_addresses'].append(str(v.split(":")[1]))

                            else:
                                target['urls'].append(v)

                elif tag == "input":
                    for i, v in items:
                        if v.lower == "password":
                            if not 'passwordFields' in target.keys():
                                target['passwordFields'] = []

                            target['passwordFields'].append(html.tostring(el))

                    target['input'] = len(items)

                elif tag in ['iframe', 'applet', 'object', 'embed', 'form']:
                    target[tag] = len(items)

        except Exception:
            error = traceback.format_exc().splitlines()[-1]
            error_msg(" parsing HTML from [ %s ]:\n\t%s" % (target['url'], error))
            if opts.verbose:
                output.put("  [!] Error parsing HTML from:\n\t%s\n" % error)

        finally:
            cxt = None

        if "email_addresses" in target.keys():
            target['email_addresses'] = list(set(target['email_addresses']))

        # grab all the headers
        for header in target['res'].headers:
            target[header] = target['res'].headers[header]

        # check title, service, and server fields for matches in defpass file
        if opts.defpass:
            services = []
            for i in [a for a in ['server', 'version', 'x-powered-by', 'version_info'] if a in target.keys()]:
                    services.append(target[i].lower())

            target['Defpass'] = []
            with open("%s/%s" % (scriptpath, DEFPASS_FILE)) as f:
                for line in f:
                    use = True
                    try:
                        if not (line.startswith("#") or line == ""):                    
                            for a in line.split(',')[0].lower().split():
                                if not a in services:
                                    use = False
                                    break

                            if use:
                                target['Defpass'].append(':'.join(line.replace("\n", '').split(',')[0:5]))

                    except Exception:
                        error = traceback.format_exc().splitlines()
                        error_msg("\n".join(error))
                        output.put("  [!] Error parsing defpass.csv:\n\t%s\n" % "\n\t".join(error))

    if "https" in target['service_name']:
        if not 'ssl-cert' in target.keys() and 'returncode' in target.keys():
            # hosts were loaded by a file that didn't contain SSL info
            output.put("  [>] Pulling SSL cert for  %s:%s" % (target['hostnames'][0], target['port']))
            import ssl
            cert = None
            try:
                cert = ssl.get_server_certificate((target['hostnames'][0], int(target['port'])),
                                                  ssl_version=ssl.PROTOCOL_TLSv1)

            except:
                try:
                    cert = ssl.get_server_certificate((target['hostnames'][0], int(target['port'])),
                                                      ssl_version=ssl.PROTOCOL_SSLv23)

                except:
                    pass

            finally:
                if cert:
                    target['ssl-cert'] = cert

            try:
                if ['ssl-cert'] in target.keys():
                    for line in target['ssl-cert'].split('\n'):
                        if "issuer" in line.lower():
                            target['SSL_Cert-Issuer'] = line.split(": ")[1]

                        elif "subject" in line.lower() and not 'SSL_Cert-Subject' in target.keys():
                            target['SSL_Cert-Subject'] = line.split(": ")[1]

                            if "*" in line.split(": ")[1]:
                                subject = line.split(": ")[1].split("*")[1]

                            else:
                                subject = line.split(": ")[1]

                            if subject in target['hostnames']:
                                target['SSL_Cert-Verified'] = "yes"

                        elif "md5" in line.lower() and not 'SSL_Cert-MD5' in target.keys():
                            target['SSL_Cert-MD5'] = line.split(": ")[1].replace(" ", '')

                        elif "sha-1" in line.lower() and not 'SSL_Cert-SHA-1' in target.keys():
                            target['SSL_Cert-SHA-1'] = line.split(": ")[1].replace(" ", '')

                        elif "algorithm" in line.lower() and not 'SSL_Cert-KeyAlg' in target.keys():
                            target['SSL_Cert-KeyAlg'] = "%s" % line.split(": ")[1]
                            # need to take another look at this one.  no seeing it atm

                        elif "not valid before" in line.lower():
                            notbefore = line.split(": ")[1].strip()
                            target['SSL_Cert-notbefore'] = notbefore

                        elif "not valid after" in line.lower():
                            notafter = line.split(": ")[1].strip()
                            target['SSL_Cert-notafter'] = notafter

                    try:
                        notbefore = datetime.strptime(str(notbefore), '%Y-%m-%d %H:%M:%S')
                        notafter = datetime.strptime(str(notafter), '%Y-%m-%d %H:%M:%S')
                        vdays = (notafter - notbefore).days
                        if datetime.now() > notafter:
                            daysleft = "EXPIRED"

                        else:
                            daysleft = (notafter - datetime.now()).days

                    except:
                        vdays = "unk"
                        daysleft = "unk"

                    target['SSL_Cert-ValidityPeriod'] = vdays
                    target['SSL_Cert-DaysLeft'] = daysleft

            except Exception:
                error = traceback.format_exc().splitlines()
                error_msg("\n".join(error))
                output.put("\n  [!] Error parsing cert:\n\t%s\n" % "\n\t".join(error))

        # Parse cert and write to file
        if 'ssl-cert' in target.keys():
            if not (os.path.exists("ssl_certs") or opts.json_min):
                os.mkdir("ssl_certs")

            open("./ssl_certs/%s_%s.cert" %
                 (target['url'].split("/")[2].split(":")[0], target['port']), 'w').write(target['ssl-cert'])

    if opts.json_min:
        output.put(target)

    else:
        if opts.sqlite:
            write_to_sqlitedb(timestamp, [target], opts)

        if opts.json:
            output.put(target)

        write_to_html(timestamp, target)
        write_to_csv(timestamp, target)
        

def write_to_sqlitedb(timestamp, targets, opts):
    if not os.path.exists("rawr_%s_sqlite3.db" % timestamp):
        try:
            cmd = 'CREATE TABLE hosts ("%s");' % str('", "'.join(flist.replace('"', "'").split(", ")))
            conn = sqlite3.connect("rawr_%s_sqlite3.db" % timestamp, timeout=10)
            conn.cursor().execute(cmd)
            conn.commit()
            conn.close()

        except Exception:
            conn = ''
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            output.put("\n  [!] Error creating SQLite db:\n\t%s\n" % "\n\t".join(error))
            opts.sqlite = False

    try:
        conn = sqlite3.connect("rawr_%s_sqlite3.db" % timestamp, timeout=45)
        cursor = conn.cursor()

        for target in targets:
            x = [" "] * len(flist.split(","))

            for i,v in target.items(): 
                if i.lower() in flist.lower().split(', '):
                    if isinstance(v, (list,)):
                        v = ";".join(v)

                    try:
                        v = str(v)

                    except UnicodeEncodeError:
                        v = unicode(v).encode('unicode_escape')

                    x[flist.lower().split(", ").index(i.lower())] = re.sub('[\n\r,]', '', "%s" % v)

            cmd = 'INSERT INTO hosts VALUES (%s);' % ("?, " * len(flist.split(", "))).rstrip(", ")
            cursor.execute(cmd, (tuple(x)))

        conn.commit()
        conn.close()

    except Exception:
        conn = ''
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        output.put("\n  [!] Error writing to SQLite db:\n\t%s\n" % "\n\t".join(error))


def write_to_csv(timestamp, target):
    x = [" "] * len(flist.split(","))

    if not os.path.exists("rawr_%s_serverinfo.csv" % timestamp):
        open("rawr_%s_serverinfo.csv" % timestamp, 'w').write(flist)

    for i, v in target.items():
        if i.lower() in flist.lower().split(', '):
            try:
                v = str(v)

            except UnicodeEncodeError:
                v = unicode(v).encode('unicode_escape')
                
            x[flist.lower().split(", ").index(i.lower())] = re.sub('[\n\r,]', '', str(v).replace('"','""'))

    try:
        open("rawr_%s_serverinfo.csv" % timestamp, 'a').write('\n"%s"' % (str('","'.join(x))))

    except Exception:
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        output.put("\n  [!] Unable to write .csv:\n\t%s\n" % "\n\t".join(error))


def write_to_html(timestamp, target):
    x = [" "] * len(flist.split(","))

    for i, v in target.items():
        if i.lower() in flist.lower().split(', '):
            try:
                v = str(v)

            except UnicodeEncodeError:
                v = unicode(v).encode('unicode_escape')

            try:
                x[flist.lower().split(", ").index(i.lower())] = re.sub('[\n\r,]', '', str(v))

            except Exception:
                error_msg("\n".join(traceback.format_exc().splitlines()[-3:]))

    try:
        open('index_%s.html' % timestamp, 'a').write("\n" + str(target['hist']) + ", " + str(','.join(x)))

    except Exception:
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        output.put("\n  [!] Unable to write .html:\n\t%s\n" % "\n\t".join(error))


# Our parsers:
def parse_csv(filename):
    targets = []
    body = False
    with open(filename) as r:
        for line in r:
            try:
                if not body:  # first line has to be headers...
                    headers = line.strip("\n").split(",")
                    body = True
                    continue

                if body and line.strip() != "":
                    target = {}
                    target['hostnames'] = []
                    line = line.strip("\n").replace('"', '').split(',')
                    for header in headers:
                        if header == "host":
                            target['ipv4'] = line[headers.index(header)]
                            target['hostnames'] = [line[headers.index(header)]]

                        elif header == "dns":
                            target['hostnames'].append(str(line[headers.index(header)]))

                        elif header == "proto":
                            target['protocol'] = line[headers.index(header)]

                        elif header == "name":
                            target['service_name'] = line[headers.index(header)]

                        elif header == "info":
                            target['service_version'] = line[headers.index(header)]

                        else:
                            target[header] = line[headers.index(header)]

                    field = [s for s in ('ipv4', 'port', 'hostnames', 'service_name', 'service_version')
                             if not s in target.keys()]
                    if len(field) == 0:
                        if "http" in target['service_name']:
                            t = [s for s in ("ssl", "https", "tls") if s in target['service_version'].lower()]
                            if len(t) > 0: 
                                target['service_tunnel'] = t[0]
                                target['service_name'] = "https"
                
                            else:
                                target['service_name'] = "http"

                        targets.append(target)

                    else:
                        field = [s for s in ('host', 'port', 'name', 'info') if not s in headers]
                        print("\t[!] Parse Error: missing required field(s): %s" % field)
                        break

            except Exception:
                error = traceback.format_exc().splitlines()
                error_msg("\n".join(error))
                print("      [!] Parse Error:\n\t%s\n" % "\n\t".join(error))

    return targets


def parse_qualys_port_service_csv(filename):
    targets = []
    body = False
    with open(filename) as r:
        for line in r:
            try:
                if line.startswith('"IP"'):
                    body = True
                    continue

                if body and line.strip() != "":
                    target = {}
                    line = line.replace('"', '').split(',')
                    target['ipv4'] = line[0]
                    target['hostnames'] = [line[1], line[0]]
                    target['service_version'] = "%s %s" % (line[2], line[5])
                    target['protocol'] = line[3]
                    target['port'] = line[4]
                    if any(s in line[5].lower() for s in ["ssl", "https", "tls"]):
                        target['service_name'] = 'https'

                    else:
                        target['service_name'] = 'http'

                    targets.append(target)

            except Exception:
                error = traceback.format_exc().splitlines()
                error_msg("\n".join(error))
                print("      [!] Parse Error:\n\t%s\n" % "\n\t".join(error))

    return targets


def parse_openvas_xml(r):     # need a scan of a server using SSL!
    targets = []
    for port in r.xpath("//report/report/ports/port"):
        try:
            target = {}
            target['protocol'] = port.text.split("/")[1].strip(")")
            target['port'] = port.text.split("(")[1].split("/")[0]
            target['service_name'] = port.text.split()[0]
            target['ipv4'] = port.xpath("host/text()")[0]
            target['hostnames'] = [target['ipv4']]

            target['service_version'] = ""
            for result in r.xpath("//report/report/results/result[host/text()='%s' and port/text()='%s' and nvt/family/text()='Product detection']" % (target['ipv4'], port.text)):
                target['service_version'] += result.xpath("description/text()")[0].split("\n")[0].replace("Detected ", '').replace("version: ",'').split(" under")[0] + ","

            targets.append(target)

        except Exception:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      [!] Parse Error:\n\t%s\n" % "\n\t".join(error))

    return targets


def parse_nexpose_xml(r):     # need a scan of a server using SSL!
    targets = []
    for node in r.xpath("//NexposeReport/nodes/node"):
        try:
            for endpoint in node.xpath("endpoints/endpoint"):
                target = {}

                target['ipv4'] = node.attrib['address']

                target['hostnames'] = list(set([x.lower() for x in node.xpath("names/name/text()")]))
                target['hostnames'].append(target['ipv4'])

                try:
                    vals = node.xpath("fingerprints/os")[0].attrib.values()
                    target['os_info'] = "(%s%s) %s" % (vals[0], "%", " ".join(vals[1:]))
                except:
                    pass  # nothing to see here

                target['protocol'] = endpoint.attrib['protocol']
                target['port'] = endpoint.attrib['port']
                target['service_name'] = endpoint.xpath("services/service/@name")[0].lower()

                try:
                    vals = endpoint.xpath("services/service/fingerprints/fingerprint")[0].attrib.values()
                    target['service_version'] = "(%s%s) %s" % (vals[0], "%", " ".join(vals[1:]))
                except:
                    pass  # nothing to see here

                targets.append(target)

        except Exception:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      [!] Parse Error:\n\t%s\n" % "\n\t".join(error))

    return targets


def parse_nexpose_simple_xml(r):     # need a scan of a server using SSL!
    targets = []
    for node in r.xpath("//NeXposeSimpleXML/devices/device"):
        try:
            for service in node.xpath("services/service"):
                target = {}
                target['ipv4'] = node.attrib['address']

                target['hostnames'] = []  # DNS? HOSTNAME?
                target['hostnames'].append(target['ipv4'])

                try:
                    target['os_info'] = node.xpath("fingerprint/description/text()")[0]
                except:
                    pass  # nothing to see here

                target['protocol'] = service.attrib['protocol']
                target['port'] = service.attrib['port']
                target['service_name'] = service.attrib['name'].lower()

                try:
                    target['service_version'] = service.xpath("fingerprint/description/text()")[0]
                except:
                    pass  # nothing to see here

                targets.append(target)

        except Exception:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      [!] Parse Error:\n\t%s\n" % "\n\t".join(error))

    return targets


def parse_qualys_scan_report_xml(r):
    targets = []
    for host in r.xpath("//ASSET_DATA_REPORT/HOST_LIST/HOST"):
        try:
            for vuln in host.xpath('VULN_INFO_LIST/VULN_INFO'):
                target = {}
                target['ipv4'] = host.xpath("IP/text()")[0]

                t = host.xpath('DNS/text()')
                if t: 
                    target['hostnames'] = [t[0].lower()]

                t = host.xpath('NETBIOS/text()')
                if t and (not t[0].lower() in target['hostnames'][0]):
                    target['hostnames'].append(t[0].lower())

                target['hostnames'].append(target['ipv4'])
                target['hostnames'] = list(set(target['hostnames']))

                t = host.xpath("OPERATING_SYSTEM/text()")
                if t and (not t[0].lower() in target['hostnames'][0]):
                    target['os_info'] = t[0]

                target['port'] = vuln.xpath("PORT/text()")[0]
                target['protocol'] = vuln.xpath("PROTOCOL/text()")[0]

                qid = vuln.xpath('QID')[0].text
                if qid in ("86000", "86001"):
                    fqdn = vuln.xpath("FQDN/text()")
                    if fqdn and not fqdn[0].lower() in target['hostnames']:
                        target['hostnames'].append(fqdn[0].lower())

                    target['service_version'] = vuln.xpath("RESULT/text()")[0]

                    if qid == "86001":  # SSL
                        target['service_name'] = 'https'
                        target['ssl-cert'] = host.xpath("VULN_INFO_LIST/VULN_INFO[PORT/text()='" + str(target['port']) +
                                                        "' and QID/text()='86002']/RESULT/text()")[0]
                        for line in target['ssl-cert'].split('(1)')[0].split('(0)'):
                            if "ISSUER NAME" in line:
                                for item in line.split('\n'):
                                    if "commonName" in item:
                                        target['SSL_Cert-Issuer'] = item.split('\t')[1]

                            if "SUBJECT NAME" in line:
                                for item in line.split('\n'):
                                    if "commonName" in item:
                                        target['SSL_Cert-Subject'] = item.split('\t')[1]

                            elif "commonName" in line and not 'SSL_Common-Name' in target.keys():
                                target['SSL_Common-Name'] = line.split("\t")[1].replace(" ", '')

                            elif "organizationName" in line and not 'SSL_Organization' in target.keys():
                                target['SSL_Organization'] = "%s" % line.split("\t")[1].replace('\n','')

                            elif "Public Key Algorithm" in line and not 'SSL_Cert-KeyAlg' in target.keys():
                                target['SSL_Cert-KeyAlg'] = "%s" % line.split("\t")[1].replace('\n','')

                            elif "Signature Algorithm" in line and not 'SSL_Cert-SigAlg' in target.keys():
                                target['SSL_Cert-SigAlg'] = "%s" % line.split("\t")[1].replace('\n','')

                            elif "RSA Public Key" in line and not 'SSL_KeyLength' in target.keys():
                                target['SSL_KeyLength'] = "%s" % line.split("\t")[1].replace('\n','')

                            elif "Valid From" in line:
                                notbefore = line.split("\t")[1].strip()
                                target['SSL_Cert-notbefore'] = notbefore

                            elif "Valid Till" in line:
                                notafter = line.split("\t")[1].strip()
                                target['SSL_Cert-notafter'] = notafter

                        try:
                            notbefore = datetime.strptime(notbefore, '%b %d %H:%M:%S %Y %Z')
                            notafter = datetime.strptime(notafter, '%b %d %H:%M:%S %Y %Z')
                            vdays = (notafter - notbefore).days
                            if datetime.now() > notafter:
                                daysleft = "EXPIRED"

                            else:
                                daysleft = (notafter - datetime.now()).days

                            target['SSL_Cert-ValidityPeriod'] = vdays
                            target['SSL_Cert-DaysLeft'] = daysleft

                        except:
                            pass

                    else:
                        target['service_name'] = 'http'

                    targets.append(target)

        except Exception:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      [!] Parse Error:\n\t%s\n" % "\n\t".join(error))

    return targets


def parse_nessus_xml(r):
    targets = []
    for node in r.xpath("//ReportHost"):
        try:  # one line can fail, and the rest of the doc completes
            for item in node.xpath('ReportItem'):
                if item.attrib['pluginName'] == "Service Detection":
                    target = {}
                    target['os_info'] = ""
                    target['hostnames'] = [node.attrib['name']]
                    for subele in node.xpath('HostProperties/tag'):

                        name = subele.get('name')
                        val = subele.text

                        if name == "host-ip":
                            target['ipv4'] = val
                            target['hostnames'].append(val)

                        elif name in ("host-fqdn", "netbios-name"):
                            target['hostnames'].append(val.lower())

                        elif name in ("operating-system", "system-type"):
                            target['os_info'] += "%s " % val

                        elif name == "mac-address":
                            target['mac_address'] = val
                    
                    target['hostnames'] = list(set(target['hostnames']))
                    target['protocol'] = item.attrib['protocol']
                    target['service_name'] = item.attrib['svc_name']
                    target['port'] = item.attrib['port']

                    try:  # because i'm not sure this format is static
                        target['service_version'] = node.xpath("ReportItem[@port='" + str(target['port']) +
                                                               "' and @pluginName='HTTP Server Type and Version" +
                                                               "']/plugin_output/text()")[0].split("\n\n")[1]

                    except:
                        pass

                    if item.attrib['svc_name'] in ["www", "http?", "https?"]:
                        target['service_name'] = "http"

                        tunnel = [s in item.xpath("./plugin_output/text()")[0].lower() for s in ["ssl", "tls"]]
                        if tunnel[0]:
                            target['service_tunnel'] = "ssl"

                        elif tunnel[1]:
                            target['service_tunnel'] = "ssl"

                        if 'service_tunnel' in target.keys():
                            target['service_name'] = "https"
                            target['ssl-cert'] = node.xpath("ReportItem[@port='" + str(target['port']) +
                                                            "' and @pluginName='SSL Certificate Information']" +
                                                            "/plugin_output/text()")[0]
                            target['SSL_Tunnel-Ciphers'] = list(node.xpath(
                                                                "ReportItem[@port='" + str(target['port']) +
                                                                "' and @pluginName='SSL / TLS Versions " +
                                                                "Supported']/plugin_output" +
                                                                "/text()")[0].split('\n')[1].split())[3].strip('.')
                            target["SSL_Tunnel-Weakest"] = target['SSL_Tunnel-Ciphers'].split('/')[0]
                            target['SSL_Cert-Issuer'] = target['ssl-cert'].split(
                                "Issuer Name")[0].split("Common Name:")[1].split('\n\n')[0].split('\n')[0].strip()
                            target['SSL_Cert-Subject'] = target['ssl-cert'].split(
                                "Serial Number")[0].split("Common Name:")[1].split('\n\n')[0].split('\n')[0].strip()

                            for line in target['ssl-cert'].split("\n\n"):
                                if "Organization" in line and not 'SSL_Organization' in target.keys():
                                    target['SSL_Organization'] = "%s" % line.split('\n')[0].split(": ")[1]

                                elif "Signature Algorithm" in line:
                                    target['SSL_Cert-KeyAlg'] = "%s" % line.split(": ")[1]

                                elif "Key Length" in line and not 'SSL_KeyLength' in target.keys():
                                    target['SSL_KeyLength'] = "%s" % line.split('\n')[1].split(": ")[1]

                                elif "Not Valid Before" in line:
                                    notbefore = line.split('\n')[0].split(": ")[1].strip('\n\n')
                                    notafter = line.split('\n')[1].split(": ")[1].strip('\n\n')
                                    target['SSL_Cert-notbefore'] = notbefore
                                    target['SSL_Cert-notafter'] = notafter

                            try:
                                notbefore = datetime.strptime(notbefore, '%b %d %H:%M:%S %Y %Z')
                                notafter = datetime.strptime(notafter, '%b %d %H:%M:%S %Y %Z')
                                vdays = (notafter - notbefore).days
                                if datetime.now() > notafter:
                                    daysleft = "EXPIRED"

                                else:
                                    daysleft = (notafter - datetime.now()).days

                                target['SSL_Cert-ValidityPeriod'] = vdays
                                target['SSL_Cert-DaysLeft'] = daysleft

                            except:
                                pass

                    else:
                        target['service_name'] = item.attrib['svc_name']

                    targets.append(target)

        except Exception:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      [!] Parse Error:\n\t%s\n" % "\n\t".join(error))

    return targets


def parse_nmap_xml(r):
    targets = []
    for el_port in r.xpath("//port"):
        try:  # one line can fail, and the rest of the doc completes
            if el_port.find("state").attrib["state"] == "open":
                target = {}
                target['hostnames'] = []
                el_host = el_port.getparent().getparent()
                for el_add in el_host.xpath("address"):
                    target[el_add.attrib['addrtype']] = el_add.attrib['addr']

                if 'ipv4' in target.keys():
                    target['hostnames'].append(target['ipv4'])

                for el_hn in el_host.xpath("*/hostname"):
                    target['hostnames'].append(str(el_hn.attrib['name']))

                target['hostnames'] = list(set(target['hostnames']))

                for el_svc in el_port.xpath("service"):
                    for key in el_svc.keys():
                        if key == "tunnel":
                            target["service_tunnel"] = el_svc.attrib[key]

                        elif key in ("product", "version", "extrainfo", "ostype"):
                            target["service_version"] = el_svc.attrib[key]

                        else: 
                            target["service_"+key] = el_svc.attrib[key]
            
                for el_scpt in el_port.xpath("script"):
                    if el_scpt.attrib['id'] == "ssl-cert":
                        target['service_name'] = 'https'
                        target['ssl-cert'] = el_scpt.attrib['output']
                        for line in target['ssl-cert'].split('\n'):
                            if "issuer" in line.lower():
                                target['SSL_Cert-Issuer'] = line.split(": ")[1]

                            elif "subject" in line.lower() and not 'SSL_Cert-Subject' in target.keys():
                                target['SSL_Cert-Subject'] = line.split(": ")[1]

                                if "*" in line.split(": ")[1]:
                                    subject = line.split(": ")[1].split("*")[1]

                                else:
                                    subject = line.split(": ")[1]

                                if subject in target['hostnames']:
                                    target['SSL_Cert-Verified'] = "yes"

                            elif "md5" in line.lower() and not 'SSL_Cert-MD5' in target.keys():
                                target['SSL_Cert-MD5'] = line.split(": ")[1].replace(" ", '')

                            elif "sha-1" in line.lower() and not 'SSL_Cert-SHA-1' in target.keys():
                                target['SSL_Cert-SHA-1'] = line.split(": ")[1].replace(" ", '')

                            elif "algorithm" in line.lower() and not 'SSL_Cert-KeyAlg' in target.keys():
                                target['SSL_Cert-KeyAlg'] = "%s" % line.split(": ")[1]
                                # need to take another look at this one.  no seeing it atm

                            elif "not valid before" in line.lower():
                                notbefore = line.split(": ")[1].strip()
                                target['SSL_Cert-notbefore'] = notbefore

                            elif "not valid after" in line.lower():
                                notafter = line.split(": ")[1].strip()
                                target['SSL_Cert-notafter'] = notafter

                        try:
                            notbefore = datetime.strptime(str(notbefore).split("+")[0], '%Y-%m-%d %H:%M:%S')
                            notafter = datetime.strptime(str(notafter).split("+")[0], '%Y-%m-%d %H:%M:%S')

                        except:  # Different format
                            notbefore = datetime.strptime(str(notbefore).split("+")[0], '%Y-%m-%dT%H:%M:%S')
                            notafter = datetime.strptime(str(notafter).split("+")[0], '%Y-%m-%dT%H:%M:%S')

                        vdays = (notafter - notbefore).days
                        if datetime.now() > notafter:
                            daysleft = "EXPIRED"

                        else:
                            daysleft = (notafter - datetime.now()).days

                        target['SSL_Cert-ValidityPeriod'] = vdays
                        target['SSL_Cert-DaysLeft'] = daysleft

                    if el_scpt.attrib['id'] == "ssl-enum-ciphers":
                        target["SSL_Tunnel-Ciphers"] = el_scpt.attrib['output'].replace("\n", ";")
                        target["SSL_Tunnel-Weakest"] = el_scpt.attrib['output'][-1].strip('\n ')

                for el_hn in el_host.xpath('owner'):
                    target['owner'].append(el_hn.attrib['name'])

                target['port'] = el_port.attrib['portid']
                target['protocol'] = el_port.attrib['protocol']

                if not 'service_name' in target.keys():
                    if target['port'] == 80:
                        target['service_name'] = "http"

                    else:
                        target['service_name'] = "unk"

                targets.append(target)

        except Exception:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      [!] Parse Error:\n\t%s\n" % "\n\t".join(error))
    
    return targets


def update(force, ckinstall, pjs_path, scriptpath):
    os.chdir(scriptpath)

    url = REPO_DL_PATH + VER_FILE
    print("  [>] Checking current versions...  \n   %s\n" % url)
    try:
        ver_data = requests.get(url).text
        defpass_ver = ver_data.split(",")[1].replace('\n', '')
        ip2c_ver = ver_data.split(",")[2].replace('\n', '')
        pjs_ver = ver_data.split(",")[3].replace('\n', '')

    except Exception:
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        print("      [x] Update Failed:\n\t%s\n" % "\n\t".join(error))
        sys.exit(1)

    if ckinstall:
        # nmap
        if not (inpath("nmap") or inpath("nmap.exe")):
            print("  [i]  NMap not found in $PATH.  You'll need to install it to use RAWR.  \n")

        else:
            proc = subprocess.Popen(['nmap', '-V'], stdout=subprocess.PIPE)
            ver = proc.stdout.read().split(' ')[2]
            main_ver = ver.split('.')[0]
            if int(main_ver) < 6: 
                print("  [i]  ** NMap %s found, but versions prior to 6.00 won't return all SSL data. **\n" % ver)

            else:
                print("  [i]  ++ NMap %s found ++\n" % ver)

        try:
            proc = subprocess.Popen([pjs_path, '-v'], stdout=subprocess.PIPE)
            pJS_curr = re.sub('[\n\r]', '', proc.stdout.read())

        except:
            pJS_curr = ""

        if force or (pjs_ver > pJS_curr) or not (inpath("phantomjs") or inpath("phantomjs.exe") or os.path.exists("data/phantomjs/bin/phantomjs") or os.path.exists("data/phantomjs/phantomjs.exe")):
            choice = ''
            if not force:        
                if pJS_curr != "" and (pjs_ver > pJS_curr):
                    txt = '\n  [i] phantomJS %s found (current is %s) - do you want to update? [Y/n]: ' % (pJS_curr, pjs_ver)
                    choice = raw_input(txt)
                else:
                    if platform.machine() == "armv7":
                        print("      [i] Please install phantomJS via apt-get.")
                        print("\n  [!] Exiting...\n\n")
                        sys.exit(0)

                    else:
                        choice = raw_input('\n  !! phantomJS was not found - do you want to install it? [Y/n]: ')
                        if not (choice.lower() in ("y", "yes", '')):
                            print("\n  [!] Exiting...\n\n")
                            sys.exit(0)
            
            if force or (choice.lower() in ("y", "yes", '')):
                # phantomJS
                pre = "phantomjs-%s" % pjs_ver
                if platform.system() in "CYGWIN|Windows":
                    fname = pre+"-windows.zip"

                elif platform.system().lower() in "darwin":
                    fname = pre+"-macosx.zip"

                elif sys.maxsize > 2**32:
                    fname = pre+"-linux-x86_64.tar.bz2"

                else:
                    fname = pre+"-linux-i686.tar.bz2"  # default is 32bit *nix

                url = "%s%s" % (PJS_REPO, fname)
                print("      [>] Pulling/installing phantomJS >\n   %s" % url)

                try:
                    fname = "data/" + fname
                    data = requests.get(url).content
                    open(fname, 'w+b').write(data)

                    if os.path.exists("data/phantomjs"):
                        if not os.access("data/phantomjs", os.W_OK):
                            import stat
                            os.chmod("data/phantomjs", stat.S_IWUSR)

                        try:
                            shutil.rmtree("data/phantomjs")

                        except Exception:
                            error = traceback.format_exc().splitlines()
                            error_msg("\n".join(error))
                            print("        [!] Failed to remove data/phantomjs:\n\t%s\n" % "\n\t".join(error))

                    if fname.endswith(".zip"):
                        import zipfile
                        zipfile.ZipFile(fname).extractall('./data')
                    else:
                        tarfile.open(fname).extractall('./data')

                    os.rename(str(os.path.splitext(fname)[0].replace(".tar", '')), "data/phantomjs")
                    os.remove(fname)

                    if platform.system().lower() in "darwin":
                        os.chmod("data/phantomjs/bin/phantomjs", 755)
                        # Mac OS X: Prevent showing the icon on the dock and stealing screen focus.
                        #   http://code.google.com/p/phantomjs/issues/detail?id=281
                        f = open("data/phantomjs/bin/Info.plist", 'w')
                        f.write(OSX_PLIST)
                        f.close()

                    print("        [+] Success\n")

                except Exception:
                    error = traceback.format_exc().splitlines()
                    error_msg("\n".join(error))
                    print("  [!] Download Failed:\n\t%s\n" % "\n\t".join(error))

        else:
            print("  [i] phantomJS %s found (current supported version) ++\n" % pJS_curr)

    defpass_curr = 0
    if os.path.exists(DEFPASS_FILE):
        ofile = open(DEFPASS_FILE).readlines()
        for line in ofile:
            if line.startswith("#"):
                defpass_curr = line.split(' ')[1].replace('\n', '')

    if not os.path.exists(DEFPASS_FILE) or force or (defpass_ver > defpass_curr):
        # defpass
        url = REPO_DL_PATH + DEFPASS_FILE.split("/")[1]
        print("  [>] Updating %s rev.%s >> rev.%s\n   %s" % (DEFPASS_FILE, defpass_curr, defpass_ver, url))
        try:
            data = requests.get(url).content
            open("data/defpass_tmp.csv", 'w').write(data)
            try: 
                os.remove(DEFPASS_FILE)

            except: 
                pass

            os.rename("data/defpass_tmp.csv", DEFPASS_FILE)
            c = len(open(DEFPASS_FILE).read().split('\n'))
            print("  [+] Success - (Contains %s entries) " % c)

        except Exception:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("        [x] Failed to parse defpass file:\n\t%s\n" % "\n\t".join(error))

    else:
        print("        [i] %s - already at rev.%s" % (DEFPASS_FILE, defpass_ver))

    ip2c_curr = 0
    if os.path.exists(IP_TO_COUNTRY):
        ofile = open(IP_TO_COUNTRY).readlines()
        for line in ofile:
            if "# Software Version" in line:
                ip2c_curr = line.split(" ")[5].replace('\n', '')
                break

    if not os.path.exists(IP_TO_COUNTRY) or force or (ip2c_ver > ip2c_curr):
        # IpToCountry
        url = REPO_DL_PATH + IP_TO_COUNTRY.split("/")[1] + ".tar.gz"
        print("\n  [>] Updating %s ver.%s >> ver.%s\n   %s" % (IP_TO_COUNTRY, ip2c_curr, ip2c_ver, url))
        try:
            data = requests.get(url).content
            open(IP_TO_COUNTRY + ".tar.gz", 'w+b').write(data)
            tarfile.open(IP_TO_COUNTRY + ".tar.gz").extractall('./data')
            os.remove(IP_TO_COUNTRY + ".tar.gz")
            print("  [+] Success\n")

        except Exception:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("  [x] Update Failed:\n\t%s\n" % "\n\t".join(error))
            sys.exit(1)

    else:
        print("\n  [i] %s - already at ver.%s\n" % (IP_TO_COUNTRY, ip2c_ver))

    print("  [i] Update Complete  ++\n\n")
    sys.exit(2)


def inpath(app):
    for path in os.environ["PATH"].split(os.pathsep):
        exe_file = os.path.join(path, app)
        if os.path.isfile(exe_file) and os.access(exe_file, os.X_OK):
            return exe_file


def error_msg(msg):
    open('error.log', 'a').write("Error:%s\n\n" % msg)


def writelog(msg, logfile, opts):
    if type(msg) == {}:
        print(msg)
    elif not (opts.json_min or opts.json):
        print(msg)
        open(logfile, 'a').write("%s\n" % msg)
