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
from warnings import simplefilter
from urlparse import urlparse
from datetime import datetime
from Queue import Queue

# Not in stdlib, but included in lib folder
sys.path.append('./lib/')
import requests
from lxml import html
from constants import *
from conf.modules import *
from conf.settings import useragent, flist, timeout, ss_delay, nthreads,\
    allow_redir, spider_thread_limit, spider_breadth_first

simplefilter("ignore")
binged = {}
binging = False
crawling = 0

threads = []
q = Queue()  # The main queue.  Holds initial host data.
output = Queue()  # The output queue - prevents output overlap


class OutThread(threading.Thread):  # Worker class that displays msgs in the 'output' queue in order and one at a time.
    def __init__(self, queue, logfile, opts):
        threading.Thread.__init__(self)
        self.queue = queue
        self.logfile = logfile
        self.opts = opts

    def run(self):
        while True:
            writelog(self.queue.get(), self.logfile, self.opts)
            self.queue.task_done()


class SiThread(threading.Thread):  # Threading class that enumerates hosts contained in the 'q' queue.
    def __init__(self, timestamp, scriptpath, pjs_path, logdir, o, opts):
        threading.Thread.__init__(self)        
        self.timestamp = timestamp
        self.scriptpath = scriptpath
        self.logdir = logdir
        self.output = o
        self.opts = opts
        self.pjs_path = pjs_path
        self.terminate = False
        self.busy = False

    def run(self):

        global binged
        global binging
        global crawling
        global q

        try:
            while not self.terminate:
                time.sleep(0.5)

                if not q.empty():
                    target = q.get()
                    self.busy = True
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

                                    except:
                                        error = traceback.format_exc().splitlines()
                                        error_msg("\n".join(error))
                                        self.output.put("  " + TCOLORS.RED + "[x]" + TCOLORS.END +
                                                        " Bing>DNS:\n\t%s\n" % "\n\t".join(error))
                                        bing_res = ""

                                    hostnames = []
                                    for line in bing_res:
                                        res = re.findall(r"<cite>(.*?)</cite>", line)
                                        if res:
                                            res = res[0].replace("https", '').replace(
                                                "http", '').replace("://", '').split('/')[0]
                                            if res != '':
                                                hostnames.append(res)

                                    if len(hostnames) > 0:
                                        # remove any duplicates from our list of domains...
                                        hostnames = list(set(hostnames))
                                        self.output.put("  " + TCOLORS.CYAN + "[+]" + TCOLORS.END +
                                                        " Bing>DNS\t: found %s DNS names for %s" %
                                                        (len(hostnames), target['ipv4']))

                                        # distribute the load
                                        for hostname in hostnames:
                                            if not hostname.strip(': ') in [target['ipv4'], "https", "http", '']:
                                                new_target = target.copy()
                                                new_target['is_bing_result'] = True
                                                new_target['hostnames'] = [hostname.strip()]
                                                self.output.put("  " + TCOLORS.CYAN + "[+]" + TCOLORS.END +
                                                                " Bing>DNS\t: [ %s ] injected into queue." %
                                                                (new_target['hostnames'][0]))
                                                q.put(new_target)

                                    else:
                                        self.output.put("  " + TCOLORS.RED + "[x]" + TCOLORS.END +
                                                        " Bing>DNS\t: found no DNS entries for %s" %
                                                        (target['ipv4']))

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
                                self.output.put("  " + TCOLORS.BLUE + "[i]" + TCOLORS.END +
                                                " Off-loaded %s:%s to the queue. [ %s:%s ]" %
                                                (new_target['hostnames'][0],
                                                 new_target['port'],
                                                 target['hostnames'][0], target['port']))

                        if len(target['hostnames']) > 0:
                            hostname = target['hostnames'][0]

                            target['url'] = prefix + hostname + port
                            self.output.put("  " + TCOLORS.GREEN + "[>]" + TCOLORS.END +
                                            " Pulling\t: " + hostname + ":" + target['port'])

                            try:
                                target['res'] = requests.get(target['url'], headers={"user-agent": useragent},
                                                             verify=False, timeout=timeout, allow_redirects=allow_redir,
                                                             proxies=self.opts.proxy_dict)

                                msg = ["  " + TCOLORS.GREEN + "[>]" + TCOLORS.END + " Finished", ""]

                            except requests.ConnectionError:
                                try:
                                    if target['res'].status_code == 401:
                                        open("./auth_fail.log", 'w').write(target['url'])

                                except:
                                    pass
                                
                                msg = ["  " + TCOLORS.RED + "[x]" + TCOLORS.END + " Not found", ""]

                            except socket.timeout:
                                msg = ["  " + TCOLORS.RED + "[x]" + TCOLORS.END + " Timed out", ""]

                            except requests.Timeout:
                                msg = ["  " + TCOLORS.RED + "[x]" + TCOLORS.END + " Timed out", ""]

                            except:
                                error = traceback.format_exc().splitlines()
                                error_msg("\n".join(error))
                                msg = ["  " + TCOLORS.RED + "[x]" + TCOLORS.END +
                                       " Error ", ":\n\t%s\n" % "\n\t".join(error)]

                            if 'res' in target.keys():
                                if self.opts.getoptions:
                                    try:
                                        res = (requests.options(target['url'], headers={"user-agent": useragent},
                                                                verify=False, timeout=timeout,
                                                                allow_redirects=allow_redir,
                                                                proxies=self.opts.proxy_dict))

                                        if 'allow' in res.headers:
                                            target['options'] = res.headers['allow'].replace(",", " | ")

                                        self.output.put("      " + TCOLORS.PURPLE + "[o]" + TCOLORS.END +
                                                        " Pulled OPTIONS : [ " + hostname + ":" + target['port'] + " ]")

                                    except requests.ConnectionError:
                                        msg = ["  " + TCOLORS.RED + "[x]" + TCOLORS.END + " Not found", ""]

                                    except socket.timeout:
                                        self.output.put("      " + TCOLORS.RED + "[x]" + TCOLORS.END +
                                                        " Timed out pulling OPTIONS: [ " +
                                                        hostname + ":" + target['port'] + " ]")

                                    except requests.Timeout:
                                        msg = ["  " + TCOLORS.RED + "[x]" + TCOLORS.END + " Timed out", ""]

                                    except:
                                        error = traceback.format_exc().splitlines()
                                        error_msg("\n".join(error))
                                        self.output.put("      " + TCOLORS.RED + "[x]" + TCOLORS.END +
                                                        " Failed pulling OPTIONS: [ %s ]\n\t%s\n" %
                                                        (hostname + ":" + target['port'], "\n\t".join(error)))

                                if not self.opts.json_min:
                                    target['hist'] = 256
                                    if not self.opts.noss and 'res' in target.keys():
                                        target['hist'] = screenshot(target, self.logdir,
                                                                    self.timestamp, self.scriptpath,
                                                                    self.opts.proxy_dict, self.pjs_path,
                                                                    self.output, (self.opts.json or self.opts.json_min))

                                if self.opts.getcrossdomain:
                                    try:
                                        res = requests.get("%s/crossdomain.xml" % target['url'], verify=False,
                                                           timeout=timeout, allow_redirects=allow_redir,
                                                           proxies=self.opts.proxy_dict)
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
                                                self.output.put("      " + TCOLORS.PURPLE + "[c]" + TCOLORS.END +
                                                                " Pulled crossdomain.xml : [ %s ]" %
                                                                (hostname + ":" + target['port']))
                                            target['crossdomain'] = "y"

                                    except requests.ConnectionError:
                                        msg = ["  " + TCOLORS.RED + "[x]" + TCOLORS.END + " Not found", ""]

                                    except socket.timeout:
                                        self.output.put("      " + TCOLORS.RED + "[x]" + TCOLORS.END +
                                                        " Timed out pulling crossdomain.xml : [ %s ]" %
                                                        (hostname + ":" + target['port']))

                                    except requests.Timeout:
                                        msg = ["  " + TCOLORS.RED + "[x]" + TCOLORS.END + " Timed out", ""]

                                    except:
                                        error = traceback.format_exc().splitlines()
                                        error_msg("\n".join(error))
                                        self.output.put("      " + TCOLORS.RED + "[x]" + TCOLORS.END +
                                                        " Failed pulling crossdomain.xml :\n\t%s\n" %
                                                        "\n\t".join(error))

                                if self.opts.getrobots:
                                    try:
                                        res = requests.get("%s/robots.txt" % target['url'], verify=False,
                                                           timeout=timeout, allow_redirects=allow_redir,
                                                           proxies=self.opts.proxy_dict)
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

                                                open("./robots/%s_%s_robots.txt" %
                                                     (hostname, target['port']), 'w').write(v)
                                                self.output.put("      " + TCOLORS.PURPLE + "[r]" + TCOLORS.END +
                                                                " Pulled robots.txt :      [ %s:%s ]" %
                                                                (hostname, target['port']))
                                            target['robots'] = "y"

                                    except requests.ConnectionError:
                                        msg = ["  " + TCOLORS.RED + "[x]" + TCOLORS.END + " Not found", ""]

                                    except socket.timeout:
                                        self.output.put("      " + TCOLORS.RED + "[x]" + TCOLORS.END +
                                                        " Timed out pulling robots.txt :      [ %s:%s ]" %
                                                        (hostname, target['port']))

                                    except requests.Timeout:
                                        msg = ["  " + TCOLORS.RED + "[x]" + TCOLORS.END + " Timed out", ""]

                                    except:
                                        error = traceback.format_exc().splitlines()
                                        error_msg("\n".join(error))
                                        self.output.put("      " + TCOLORS.RED + "[x]" + TCOLORS.END +
                                                        " Failed pulling robots.txt :\n\t%s\n" % "\n\t".join(error))

                                if self.opts.crawl and not self.opts.json_min:
                                    if not os.path.exists("maps"):
                                        try:
                                            os.makedirs("maps")

                                        except:
                                            pass

                                    while crawling >= spider_thread_limit:
                                        time.sleep(0.1)

                                    crawling += 1
                                    crawl(target, self.logdir, self.timestamp, self.opts)
                                    crawling -= 1

                                parsedata(target, self.timestamp, self.scriptpath, self.opts)
                                self.output.put("%s  [ %s%s ]%s" % (msg[0], hostname, port, msg[1]))

                    except:
                        error = traceback.format_exc().splitlines()
                        error_msg("\n".join(error))
                        self.output.put("  " + TCOLORS.RED + "[x]" + TCOLORS.END +
                                        " Failed : [ %s:%s ]\n\t%s\n" % (hostname, target['port'], "\n\t".join(error)))

                    self.busy = False

                    busy_count = 0
                    for t in threads:
                        if t.busy:
                            busy_count += 1

                    self.output.put("  " + TCOLORS.BLUE + "[i]" + TCOLORS.END +
                                    " Main queue size [ %s ] - Threads Busy/Total [ %s/%s ]" %
                                    (str(q.qsize()), busy_count, nthreads))

                    q.task_done()

        except KeyboardInterrupt:
            pass


def screenshot(target, logdir, timestamp, scriptpath, proxy, pjs_path, o, silent):
    filename = "%s/%s_%s_%s.png" % ("%s/images" % logdir, urlparse(target['url']).netloc,
                                    timestamp, target['port'])
    err = '.'

    try:
        if not os.path.exists(filename):
            lp = "%s/rawr_%s.log" % (logdir, timestamp)
            if silent:
                lp = "/dev/null"

            with open(lp, 'ab') as log_pipe:
                start = datetime.now()
                cmd = [pjs_path]

                if proxy:
                    cmd.append("--proxy=%s" % proxy['http'])  # Same ip:port is used for both http and https.

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
                o.put("      " + TCOLORS.CYAN + "[+]" + TCOLORS.END + " Screenshot :     [ %s ]" % target['url'])

                try:  # histogram time!
                    r, g, b, c = 0, 0, 0, 0
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
                o.put("      " + TCOLORS.RED + "[x]" + TCOLORS.END +
                      " Screenshot :     [ %s ] Failed - 0 byte file. Deleted." % target['url'])
                try:
                    os.remove(filename)
                    shutil.copyfile(scriptpath + "/data/error.png", "%s/images/error.png" % logdir)

                except:
                    pass
        else:
            o.put("      " + TCOLORS.RED + "[x]" + TCOLORS.END +
                  " Screenshot :     [ %s ] Failed - %s" % (target['url'], err))
            shutil.copyfile(scriptpath + "/data/error.png", "%s/images/error.png" % logdir)

    except:
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        o.put("      " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
              " Screenshot :     [ %s ] Failed\n\t%s\n" % (target['url'], "\n\t".join(error)))


def crawl(target, logdir, timestamp, opts):  # Our Spidering function.
    output.put("      " + TCOLORS.GREEN + "[>]" + TCOLORS.END + " Spidering  :     [ %s ]" % target['url'])

    def recurse(url_t1, urls_t2, tabs, depth):
        url_t1 = url_t1.strip('"/\; ()')

        for url_t2 in urls_t2:
            url_t2 = url_t2.strip('"/\; ()').replace("/#", "")

            if opts.verbose:
                output.put("      " + TCOLORS.BLUE + "[i]" + TCOLORS.END +
                           " [%s] threads %s/%s - depth %s/%s - sec %d/%s - urls %s/%s" %
                           (target['url'], crawling, opts.spider_thread_limit, depth, opts.spider_depth,
                            (datetime.now() - time_start).total_seconds(),
                            opts.spider_timeout, len(list(set(urls_visited))), opts.spider_url_limit))

            if len(list(set(urls_visited))) > opts.spider_url_limit:
                if opts.verbose:
                    output.put("      " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                               " Spidering stopped at depth - %s:   [ %s ] - URL limit reached" %
                               (str(depth), target['url']))

                break

            elif (datetime.now() - time_start).total_seconds() > opts.spider_timeout:
                if opts.verbose:
                    output.put("      " + TCOLORS.YELLOW + "[!]" +
                               TCOLORS.END + " Spidering stopped at depth - %s:   [ %s ] - Timed out" %
                               (str(depth), target['url']))

                break

            if not url_t2 in ("https://ssl", "http://www", "http://", "http://-", "http:", "https:"):  # ga junk
                coll.append((url_t1.replace(":", "-"), url_t2.replace(":", "-")))

                if not (spider_breadth_first
                        or (url_t2 in urls_visited or (opts.spider_url_blacklist and (url_t2 in url_blacklist)))):
                    open('%s/maps/links_%s_%s__%s.txt' %
                         (logdir, hname, target['port'], timestamp), 'a').write(tabs +
                                                                                url_t2.encode('utf-8', 'ignore') + "\n")

                if not (url_t2 in urls_visited or (opts.spider_url_blacklist and (url_t2 in url_blacklist))):
                    urls_visited.append(url_t2)
                    p = urlparse(url_t2)

                    if p.path.split(".")[-1].lower() in DOC_TYPES and url_t2 not in target['docs']:
                        target['docs'].append(str(url_t2))

                        try:
                            open('%s/maps/docs_%s_%s__%s.txt' %
                                 (logdir, hname, target['port'], timestamp), 'a').write(url_t2 + "\n")

                        except:
                            pass

                    else:
                        if opts.spider_follow_subdomains:
                            url_t2_hn = ".".join(p.netloc.split(".")[-2:])

                        else:
                            url_t2_hn = p.netloc

                        if url_t2_hn in url_t1 or url_t2_hn in opts.alt_domains:
                            try:
                                dat = requests.get(url_t2, headers={"user-agent": useragent, "referer": url_t1},
                                                   verify=False, timeout=opts.spider_url_timeout,
                                                   allow_redirects=allow_redir,
                                                   proxies=opts.proxy_dict).text.replace("\n", "")

                                if dat != "":
                                    urls_t3 = []
                                    for u in list(set(re.findall(URL_REGEX, dat, re.I))):
                                        urls_t3.append(u.split('"')[0].split("'")[0].split(
                                                       "<")[0].split("--")[0].rstrip('%)/.'))  # supplement the regex

                                    try:  # parse the html for tags w/ href or source
                                        cxt = html.fromstring(dat)
                                        for el in cxt.iter():
                                            try:
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
                                                                if not v.split("//")[0] in ("http:", "https:"):
                                                                    v = v.replace("../", '')
                                                                    if not v.startswith("/"):
                                                                        v = "/" + v

                                                                    v = p.scheme + "://" + p.netloc + v
                                                                    urls_t3.append(v)

                                            except Exception:
                                                e = traceback.format_exc().splitlines()[-1]
                                                error_msg(" [spider] parsing HTML element [ %s ]:\n\t%s" %
                                                          (target['url'], e))

                                    except:
                                        e = traceback.format_exc().splitlines()[-1]
                                        error_msg(" [spider] parsing HTML from [ %s ]:\n\t%s" % (target['url'], e))

                                    urls_t3 = list(set(urls_t3))

                                    if len(urls_t3) > 0:
                                        if not (len(list(set(urls_visited))) > opts.spider_url_limit
                                                or depth >= opts.spider_depth
                                                or (datetime.now() - time_start).total_seconds() > opts.spider_timeout):
                                            if spider_breadth_first:  # Not a 'tree' until we move to nosqlite
                                                urls_to_crawl.put([url_t2, urls_t3, "\t", depth + 1])

                                            else:
                                                recurse(url_t2, urls_t3, tabs + "\t", depth + 1)

                            except:
                                e = traceback.format_exc().splitlines()
                                error_msg(" [spider] pulling [ %s ]:\n\t%s" % (target['url'], e))

    if opts.spider_url_blacklist:
        if os.path.isfile(opts.spider_url_blacklist):
            url_blacklist = open(opts.spider_url_blacklist).read().split('\n')
            output.put("        " + TCOLORS.BLUE + "[i]" + TCOLORS.END + " Spidering - blacklisting %s urls." %
                       (len(url_blacklist)-1))

        else:
            output.put("        " + TCOLORS.BLUE + "[i]" + TCOLORS.END +
                       " Spidering - unable to find blacklist file - " % opts.spider_url_blacklist)

    coll, urls_visited, target['docs'] = [], [], []
    hname = urlparse(target['url']).netloc
    time_start = datetime.now()

    if spider_breadth_first:
        urls_to_crawl = Queue()
        urls_to_crawl.put([target['url'], [target['url']], "\t", 1])
        while not urls_to_crawl.empty():
                x, y, t, d = urls_to_crawl.get()
                recurse(x, y, t, d)

        urls_to_crawl = None

    else:  # length first
        recurse(target['url'], [target['url']], "\t", 1)

    target['doc_count'] = len(target['docs'])

    if len(coll) > 1:
        try: 
            import pygraphviz as pgv
            output.put("      " + TCOLORS.CYAN + "[+]" + TCOLORS.END +
                       " Finished spider: [ %s ] - building graph..." % target['url'])

            # Graph creation
            gr = pgv.AGraph(splines='ortho', rankdir='LR')
            gr.node_attr['shape'] = 'rect'

            c = []
            for x, y in coll:  # Add nodes and edges
                if not x in c:
                    c.append(x)

                if not (x == y or y in c):
                    c.append(y)

            if opts.verbose:
                output.put("      " + TCOLORS.BLUE + "[i]" + TCOLORS.END +
                           " Processing data for [ %s ]:   %s nodes / %s unique" %
                           (target['url'], len(c), len(list(set(c)))))

            for node in c:
                if node == target['url'].replace(':', '-'):
                    gr.add_node(node, root=True, shape=ROOT_NODE_SHAPE, color=ROOT_NODE_COLOR)

                elif not urlparse(target['url']).netloc in node:
                    gr.add_node(node, shape=EXTERNAL_NODE_SHAPE, color=EXTERNAL_NODE_COLOR)

                else:
                    gr.add_node(node)

            if opts.verbose:
                output.put("      " + TCOLORS.BLUE + "[i]" + TCOLORS.END +
                           " Processing colls for [ %s ]:   %s colls" % (target['url'], len(coll)))

            for x, y in [z for z in coll if z[0] != z[1]]:
                gr.add_edge((x, y))

            # Draw as PNG
            gr.layout(prog='dot')
            # will get a warning if the graph is too large - not fatal
            f = '%s/maps/diagram_%s_%s__%s.png' % (logdir, urlparse(target['url']).netloc, target['port'], timestamp)

            if opts.verbose:
                output.put("      " + TCOLORS.BLUE + "[i]" + TCOLORS.END +
                           " Drawing diagram for [ %s ]: %s" % (target['url'], f))

            gr.draw(f)
            target['diagram'] = f

        except:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            output.put("\n    " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                       " Unable to create site chart: [ %s ]\n\t%s\n" % (target['url'], "\n\t".join(error)))


def parsedata(target, timestamp, scriptpath, opts):  # Takes raw site response and parses it.
    for i, v in target.items():
        target[i] = target[str(i)]

    # identify country if possible
    try:
        o1, o2, o3, o4 = target['ipv4'].split('.')
        ipnum = (int(o1)*16777216) + (int(o2)*65536) + (int(o3)*256) + int(o4)
        with open("%s/%s" % (scriptpath, IP_TO_COUNTRY)) as f:
            for c, l in enumerate(f):
                if l != "" and not "#" in l:
                    l = l.replace('"', '').split(',')
                    if int(l[1]) > ipnum > int(l[0]):
                        target['country'] = "[%s]-%s" % (l[4], l[6].strip('\n'))
                        break

    except:
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        output.put("  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                   " IPtoCountry parse error:\n\t%s\n" % "\n\t".join(error))

    if 'res' in target.keys():
        # eat cookie now....omnomnom
        if len(target['res'].cookies) > 0:    
            try:
                os.mkdir("cookies")

            except:
                pass

            open("./cookies/%s_%s.txt" %
                 (urlparse(target['url']).netloc, target['port']), 'w').write(str(target['res'].cookies))
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

                        if field == "comments":
                            i = i.replace('<', '&lt;')

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
                    output.put("  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END + " skipping %s - invalid modtype" % field)

            except:
                error = traceback.format_exc().splitlines()
                error_msg("\n".join(error))
                output.put("  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                           " skipping module '%s' :\n\t%s\n" % (field, "\n\t".join(error)))

        # not bound to specific elements/attributes
        target['urls'] = []
        for url in re.findall(URL_REGEX, target['res'].text, re.I):
            target['urls'].append(url.split("'")[0].rstrip(')/.'))

        # parse the html for different element types
        if target['res'].content != "":
            try:
                cxt = html.fromstring(target['res'].content)
                for el in cxt.iter():
                    try:
                        items = el.items()
                        tag = el.tag

                        # user-defined modules
                        for n, s, t in [m for m in parsermods if str(m[1][0]).lower() == str(tag).lower()]:
                            # ^ only mods that reference the current element tag
                            val = ""
                            try:
                                if "text" in s[1] and el.text is None:
                                    val = el.text

                                val += " %s" % (" ".join([v for i, v in items if i in s[1]]))

                                if val != "":
                                    r = (re.findall(s[2], val, re.I))

                                    if t == 3:
                                        for i in r:
                                            if not n in target.keys():
                                                target[n] = []

                                            target[n].append(i)

                                    elif t == 4:
                                        if len(r) > 0:
                                            target[n] = ["True"]
                                        else:
                                            target[n] = ["False"]

                                    elif t == 5:
                                        target[n] = [len(r)]

                                    else:
                                        raise("invalid modtype - %s" % t)

                            except:
                                error = traceback.format_exc().splitlines()
                                error_msg("\n".join(error))
                                output.put("  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                                           " skipping module '%s':\n\t%s\n" % (n, "\n\t".join(error)))

                        # some default checks
                        if tag == "meta":
                            for i, v in items:
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
                        error_msg(" parsing HTML element [ %s ]:\n\t%s" % (target['url'], error))
                        if opts.verbose:
                            output.put("  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                                       " Error parsing HTML element:\n\t%s\n" % error)

            except Exception:
                error = traceback.format_exc().splitlines()[-1]
                error_msg(" parsing HTML from [ %s ]:\n\t%s" % (target['url'], error))
                if opts.verbose:
                    output.put("  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                               " Error parsing HTML from:\n\t%s\n" % error)

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

                    except:
                        error = traceback.format_exc().splitlines()
                        error_msg("\n".join(error))
                        output.put("  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                                   " Error parsing defpass.csv:\n\t%s\n" % "\n\t".join(error))

    if "https" in target['service_name']:
        if not 'ssl-cert' in target.keys() and 'returncode' in target.keys():
            # ^ hosts were loaded by a file that didn't contain SSL info
            output.put("  " + TCOLORS.GREEN + "[>]" + TCOLORS.END +
                       " Pulling SSL cert for  %s:%s" % (target['hostnames'][0], target['port']))

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
                    notbefore = ""
                    notafter = ""
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
                            # need to take another look at this one.  not seeing it atm

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

            except:
                error = traceback.format_exc().splitlines()
                error_msg("\n".join(error))
                output.put("\n  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                           " Error parsing cert:\n\t%s\n" % "\n\t".join(error))

        # Parse cert and write to file
        if not opts.json_min and 'ssl-cert' in target.keys():
            try:
                os.mkdir("ssl_certs")

            except:
                pass

            open("./ssl_certs/%s_%s.cert" %
                 (urlparse(target['url']).netloc, target['port']), 'w').write(target['ssl-cert'])

    if opts.json or opts.json_min:
        output.put(target)

    if not opts.json_min:
        if opts.sqlite:
            write_to_sqlitedb(timestamp, [target], opts)

        write_to_html(timestamp, target)
        write_to_csv(timestamp, target)
        

def write_to_sqlitedb(timestamp, targets, opts):
    try:
        conn = sqlite3.connect("rawr_%s_sqlite3.db" % timestamp, timeout=45)
        cursor = conn.cursor()

        for target in targets:
            x = [" "] * len(flist.split(","))

            for i, v in target.items():
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

    except:
        conn = None
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        output.put("\n  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                   " Error writing to SQLite db:\n\t%s\n" % "\n\t".join(error))


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
                
            x[flist.lower().split(", ").index(i.lower())] = re.sub('[\n\r,]', '', str(v).replace('"', '""'))

    try:
        open("rawr_%s_serverinfo.csv" % timestamp, 'a').write('\n"%s"' % (str('","'.join(x))))

    except:
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        output.put("\n  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                   " Unable to write .csv:\n\t%s\n" % "\n\t".join(error))


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

            except:
                error_msg("\n".join(traceback.format_exc().splitlines()[-3:]))

    try:
        open('index_%s.html' % timestamp, 'a').write("\n" + str(target['hist']) + ", " + str(','.join(x)))

    except:
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        output.put("\n  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                   " Unable to write .html:\n\t%s\n" % "\n\t".join(error))


# Our parsers:
def parse_csv(filename):
    targets = []
    body = False
    with open(filename) as r:
        for line in r:
            try:
                if not body:  # first line has to define column headers
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

                    # Check for missing fields
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

            except:
                error = traceback.format_exc().splitlines()
                error_msg("\n".join(error))
                print("      " + TCOLORS.YELLOW + "[!]" + TCOLORS.END + " Parse Error:\n\t%s\n" % "\n\t".join(error))

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
                    target['ipv4'], hn, sv, target['protocol'], target['port'], sn = line.replace('"', '').split(',')
                    target['hostnames'] = [hn, target['ipv4']]
                    target['service_version'] = "%s %s" % (sv, sn)
                    if any(s in sn.lower() for s in ["ssl", "https", "tls"]):
                        target['service_name'] = 'https'

                    else:
                        target['service_name'] = 'http'

                    targets.append(target)

            except:
                error = traceback.format_exc().splitlines()
                error_msg("\n".join(error))
                print("      " + TCOLORS.YELLOW + "[!]" + TCOLORS.END + " Parse Error:\n\t%s\n" % "\n\t".join(error))

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
            for result in r.xpath("//report/report/results/result[host/text()=" +
                                  "'%s'and port/text()='%s' and nvt/family/text()='Product detection']" %
                                  (target['ipv4'], port.text)):
                target['service_version'] += result.xpath("description/text()")[0].split("\n")[0].replace(
                    "Detected ", '').replace("version: ", '').split(" under")[0] + ","

            targets.append(target)

        except:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      " + TCOLORS.YELLOW + "[!]" + TCOLORS.END + " Parse Error:\n\t%s\n" % "\n\t".join(error))

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

        except:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      " + TCOLORS.YELLOW + "[!]" + TCOLORS.END + " Parse Error:\n\t%s\n" % "\n\t".join(error))

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

        except:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      " + TCOLORS.YELLOW + "[!]" + TCOLORS.END + " Parse Error:\n\t%s\n" % "\n\t".join(error))

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
                        notbefore = ""
                        notafter = ""
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
                                target['SSL_Organization'] = "%s" % line.split("\t")[1].replace('\n', '')

                            elif "Public Key Algorithm" in line and not 'SSL_Cert-KeyAlg' in target.keys():
                                target['SSL_Cert-KeyAlg'] = "%s" % line.split("\t")[1].replace('\n', '')

                            elif "Signature Algorithm" in line and not 'SSL_Cert-SigAlg' in target.keys():
                                target['SSL_Cert-SigAlg'] = "%s" % line.split("\t")[1].replace('\n', '')

                            elif "RSA Public Key" in line and not 'SSL_KeyLength' in target.keys():
                                target['SSL_KeyLength'] = "%s" % line.split("\t")[1].replace('\n', '')

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

        except:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      " + TCOLORS.YELLOW + "[!]" + TCOLORS.END + " Parse Error:\n\t%s\n" % "\n\t".join(error))

    return targets


def parse_nessus_xml(r):
    targets = []
    for node in r.xpath("//ReportHost"):
        try:  # one line can fail, and the rest of the doc completes
            for item in node.xpath('ReportItem'):
                notbefore = ""
                notafter = ""
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

        except:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      " + TCOLORS.YELLOW + "[!]" + TCOLORS.END + " Parse Error:\n\t%s\n" % "\n\t".join(error))

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

				target["service_version"] = []
                for el_svc in el_port.xpath("service"):
                    for key in el_svc.keys():
                        if key == "tunnel":
                            target["service_tunnel"] = el_svc.attrib[key]

                        elif key in ("product", "version", "extrainfo", "ostype"):
                            target["service_version"].append(el_svc.attrib[key])

                        else: 
                            target["service_"+key] = el_svc.attrib[key]
            
				if target["service_version"] != []:
					target["service_version"] = ' '.join(target["service_version"])

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

        except:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      " + TCOLORS.YELLOW + "[!]" + TCOLORS.END + " Parse Error:\n\t%s\n" % "\n\t".join(error))
    
    return targets


def update(force, ckinstall, pjs_path, scriptpath):
    os.chdir(scriptpath)

    url = REPO_DL_PATH + VER_FILE
    print("  " + TCOLORS.GREEN + "[>]" + TCOLORS.END + " Checking current versions...  \n\t%s\n" % url)
    try:
        rawr_ver, defpass_ver, ip2c_ver, pjs_ver = requests.get(url).text.replace('\n', '').split(",")

    except:
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        print("      " + TCOLORS.RED + "[x]" + TCOLORS.END + " Update Failed:\n\t%s\n" % "\n\t".join(error))
        sys.exit(1)

    if ckinstall:
        # nmap
        if not (inpath("nmap") or inpath("nmap.exe")):
            print("  " + TCOLORS.BLUE + "[i]" + TCOLORS.END +
                  "  NMap not found in $PATH.  You'll need to install it to use RAWR.  \n")

        else:
            proc = subprocess.Popen(['nmap', '-V'], stdout=subprocess.PIPE)
            ver = proc.stdout.read().split(' ')[2]
            if int(ver.split('.')[0]) < 6:  # 6.00 is when ssl_num_ciphers.nse was added.
                print("  " + TCOLORS.BLUE + "[i]" + TCOLORS.END +
                      "  ** NMap %s found, but versions prior to 6.00 won't return all SSL data. **\n" % ver)

            else:
                print("  " + TCOLORS.BLUE + "[i]" + TCOLORS.END + "  ++ NMap %s found ++\n" % ver)

        try:
            proc = subprocess.Popen([pjs_path, '-v'], stdout=subprocess.PIPE)
            pjs_curr = re.sub('[\n\r]', '', proc.stdout.read())

        except:
            pjs_curr = 0

        if force or (pjs_ver > pjs_curr):
            if not force:
                if pjs_curr != 0 and (pjs_ver > pjs_curr):
                    choice = raw_input("\n  " + TCOLORS.BLUE + "[i]" + TCOLORS.END +
                                       " phantomJS %s found (current is %s) - do you want to update? [Y/n]: " %
                                       (pjs_curr, pjs_ver))
                    if choice.lower() in ("y", "yes", ''):
                        force = True

                else:
                    if platform.machine() == "armv7":
                        # Not a binary compiled for arm out there for DL just yet.
                        # I'll put it as a download in the RAWR repo if someone can provide it.
                        print("      " + TCOLORS.BLUE + "[i]" + TCOLORS.END + " Please install phantomJS via apt-get.")
                        print("\n  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END + " Exiting...\n\n")
                        sys.exit(0)

                    else:
                        choice = raw_input("\n  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                                           " phantomJS was not found - do you want to install it? [Y/n]: ")
                        if not (choice.lower() in ("y", "yes", '')):
                            print("\n  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END + " Exiting...\n\n")
                            sys.exit(0)

                        else:
                            force = True

            if force:
                # phantomJS
                pre = "phantomjs-%s" % pjs_ver
                if platform.system() in "CYGWIN|Windows":
                    fname = pre + "-windows.zip"
                    url = PJS_REPO + fname

                elif platform.system().lower() in "darwin":
                    fname = pre + "-macosx.zip"
                    url = PJS_REPO + fname

                #elif platform.machine() == "armv7":
                #   fname = "-arm7.tar.gz"
                #   url = REPO_DL_PATH + fname

                elif sys.maxsize > 2**32:
                    fname = pre + "-linux-x86_64.tar.bz2"
                    url = PJS_REPO + fname

                else:
                    fname = pre + "-linux-i686.tar.bz2"  # default is 32bit *nix
                    url = PJS_REPO + fname

                print("  " + TCOLORS.GREEN + "[>]" + TCOLORS.END + " Pulling/installing phantomJS >\n\t%s" % url)

                try:
                    data = requests.get(url).content
                    open("data/" + fname, 'w+b').write(data)

                    if os.path.exists("data/phantomjs"):
                        if not os.access("data/phantomjs", os.W_OK):
                            import stat
                            os.chmod("data/phantomjs", stat.S_IWUSR)

                        try:
                            shutil.rmtree("data/phantomjs")

                        except:
                            error = traceback.format_exc().splitlines()
                            error_msg("\n".join(error))
                            print("        " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                                  " Failed to remove data/phantomjs:\n\t%s\n" % "\n\t".join(error))

                    if fname.endswith(".zip"):
                        import zipfile
                        zipfile.ZipFile("data/" + fname).extractall('./data')
                    else:
                        tarfile.open("data/" + fname).extractall('./data')

                    os.rename("data/" + str(os.path.splitext(fname)[0].replace(".tar", '')), "data/phantomjs")
                    os.remove("data/" + fname)

                    if platform.system().lower() in "darwin":
                        os.chmod("data/phantomjs/bin/phantomjs", 755)
                        # Mac OS X: Prevent showing the icon on the dock and stealing screen focus.
                        #   http://code.google.com/p/phantomjs/issues/detail?id=281
                        f = open("data/phantomjs/bin/Info.plist", 'w')
                        f.write(OSX_PLIST)
                        f.close()

                    print("      " + TCOLORS.CYAN + "[+]" + TCOLORS.END + " Success\n")

                except:
                    error = traceback.format_exc().splitlines()
                    error_msg("\n".join(error))
                    print("  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                          " Download Failed:\n\t%s\n" % "\n\t".join(error))

        else:
            print("  " + TCOLORS.BLUE + "[i]" + TCOLORS.END +
                  " phantomJS %s found (current supported version) ++\n" % pjs_curr)

    try:
        defpass_curr = open(DEFPASS_FILE).readline().split(' ')[1].replace('\n', '')

    except:
        defpass_curr = 0

    if force or (defpass_ver > defpass_curr):
        # defpass
        if not force:
            choice = raw_input("\n  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                               " Update defpass.csv from rev.%s to rev.%s? [Y/n]: " % (defpass_curr, defpass_ver))
            if choice.lower() in ("y", "yes", ''):
                force = True

        if force:
            url = REPO_DL_PATH + DEFPASS_FILE.split("/")[1]
            print("  " + TCOLORS.GREEN + "[>]" + TCOLORS.END + " Updating %s rev.%s >> rev.%s\n\t%s" %
                  (DEFPASS_FILE, defpass_curr, defpass_ver, url))
            try:
                data = requests.get(url).content
                open("data/defpass_tmp.csv", 'w').write(data)
                try:
                    os.remove(DEFPASS_FILE)

                except:
                    pass

                os.rename("data/defpass_tmp.csv", DEFPASS_FILE)

                c = 0
                with open(DEFPASS_FILE) as f:
                    for c, l in enumerate(f):
                        pass

                print("      " + TCOLORS.CYAN + "[+]" + TCOLORS.END + " Success - (Contains %s entries) " % c)

            except:
                error = traceback.format_exc().splitlines()
                error_msg("\n".join(error))
                print("  " + TCOLORS.RED + "[x]" + TCOLORS.END + " Failed to parse defpass file:\n\t%s\n" %
                      "\n\t".join(error))

    else:
        print("  " + TCOLORS.BLUE + "[i]" + TCOLORS.END + " %s - already at rev.%s" % (DEFPASS_FILE, defpass_ver))

    ip2c_curr = 0
    try:
        with open(IP_TO_COUNTRY) as f:
            for c, l in enumerate(f):
                if "# Software Version" in l:
                    ip2c_curr = l.split(" ")[5].replace('\n', '')
                    break

    except:
        pass

    if force or (ip2c_ver > ip2c_curr):
        # IpToCountry
        if not force:
            choice = raw_input("\n  " + TCOLORS.YELLOW + "[!]" + TCOLORS.END +
                               " Update IpToCountry.csv from rev.%s to rev.%s? [Y/n]: " % (ip2c_curr, ip2c_ver))
            if choice.lower() in ("y", "yes", ''):
                force = True

        if force:
            url = REPO_DL_PATH + IP_TO_COUNTRY.split("/")[1] + ".tar.gz"
            print("\n  " + TCOLORS.GREEN + "[>]" + TCOLORS.END + " Updating %s ver.%s >> ver.%s\n\t%s" %
                  (IP_TO_COUNTRY, ip2c_curr, ip2c_ver, url))
            try:
                data = requests.get(url).content
                open(IP_TO_COUNTRY + ".tar.gz", 'w+b').write(data)
                tarfile.open(IP_TO_COUNTRY + ".tar.gz").extractall('./data')
                os.remove(IP_TO_COUNTRY + ".tar.gz")
                print("      " + TCOLORS.CYAN + "[+]" + TCOLORS.END + " Success\n")

            except:
                error = traceback.format_exc().splitlines()
                error_msg("\n".join(error))
                print("  " + TCOLORS.RED + "[x]" + TCOLORS.END + " Update Failed:\n\t%s\n" % "\n\t".join(error))
                sys.exit(1)

    else:
        print("\n  " + TCOLORS.BLUE + "[i]" + TCOLORS.END + " %s - already at ver.%s\n" % (IP_TO_COUNTRY, ip2c_ver))

    print("  " + TCOLORS.CYAN + "[+]" + TCOLORS.END + " Update Complete  ++\n\n")
    sys.exit(2)


def inpath(app):
    for path in os.environ["PATH"].split(os.pathsep):
        exe_file = os.path.join(path, app)
        if os.path.isfile(exe_file) and os.access(exe_file, os.X_OK):
            return exe_file


def error_msg(msg):
    open('error.log', 'a').write("Error:%s\n\n" % msg)


def writelog(msg, logfile, opts):
    if not (opts.json or opts.json_min) or type(msg) == dict:
        print(msg)

    if not opts.json_min:
        open(logfile, 'a').write("%s\n" % msg)
