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
import traceback
import colorsys
import socket
import shelve
from warnings import simplefilter
from urlparse import urlparse
from glob import glob
from Queue import Queue
from multiprocessing import Process

# local imports
import requests
from PIL import Image  # logo size, histogram, and list of Exif tags for file enum
from lib.constants import *
from conf.modules import *
from conf.settings import useragent, flist, timeout, ss_delay, nthreads, allow_redir, use_ghost
from rawr_meta import *
meta_parser = Meta_Parser()

# Non stdlib
try:
    from lxml import html
    import pygraphviz as pgv
    if use_ghost:
        from ghost import Ghost

except Exception, e:
    from lib.banner import *
    print(banner)
    if isinstance(e, ImportError) or str(e) == "Ghost.py requires PySide or PyQt4":
        print("\t%s[x]%s - Run install.sh to get set up." % (TC.RED, TC.END) + str(e))

    else:
        print(e)
        exit(1)


timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
platform_type = platform.machine()
simplefilter("ignore")  # ignore warnings
dns_cache = {}  # bing result cache - to avoid duplicate bings
binging = False  # to make sure one bing happens at a time
outs = [] # list of urls that have already been added to the HTML/CSV docs
crawling = 0  # a count of the number of crawls happening simultaneously

threads = []  # contains handles for each thread
q = Queue()  # The main queue.  Holds db reference for each target.
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
    def __init__(self, db, timestamp, scriptpath, pjs_path, logdir, o, opts):
        threading.Thread.__init__(self)
        self.timestamp = timestamp
        self.scriptpath = scriptpath
        self.logdir = logdir
        self.output = o
        self.opts = opts
        self.pjs_path = pjs_path
        self.terminate = False
        self.busy = False
        self.db = db

    def run(self):

        global dns_cache
        global binging
        global crawling
        global q
        global outs

        while not self.terminate:
            time.sleep(0.5)

            if q and not q.empty():
                task = q.get()
                self.busy = True

                target = dict( self.db[task[0]][task[1]] )  # the dict, rather than a link to the db...

                if task[1] == '.':
                    hostname = target['ipv4']
                    
                else:
                    hostname = task[1]

                port = ''
                try:
                    prefix = "http://"
                    if 'service_tunnel' in target.keys():                        
                        if target['service_tunnel'] == 'ssl':
                            prefix = "https://"

                    if not target['port'] in ["80", "443"]:
                        port = ":" + target['port']

                    if self.opts.dns and (not 'is_dns_result' in target.keys()):
                        # Don't do Bing>DNS lookups for non-routable IPs
                        if not re.findall(NRIP_REGEX, target['ipv4']):
                            if target['ipv4'] in dns_cache:
                                self.output.put("  %s[.]%s RevDNS\t: %s (%s) - pulling from cache..." % (TC.PURPLE, TC.END, target['ipv4'], target['hostnames'][0]) )
                                hostnames = dns_cache[target['ipv4']]
                            
                            else:
                                while binging:  # The intention here is to avoid flooding Bing with requests.
                                    time.sleep(0.5)

                                binging = True
                                self.output.put("  %s[@]%s Bing RevDNS\t: %s" % (TC.PURPLE, TC.END, target['ipv4']))
                                cookies = dict(SRCHHPGUSR = 'NRSLT=50')

                                nxt, old_res, hostnames = (1, [], [])

                                while True:
                                    try:
                                        bing_res = requests.get("http://www.bing.com/search?q=ip%3a" + target['ipv4'] +
                                                                    '&format=rss&first=%s' % nxt,
                                                                headers = {"user-agent": useragent},
                                                                verify = False,
                                                                timeout = timeout,
                                                                allow_redirects = allow_redir,
                                                                proxies = self.opts.proxy_dict,
                                                                cookies = cookies).content

                                    except:
                                        error = traceback.format_exc().splitlines()
                                        error_msg("\n".join(error))
                                        self.output.put("  %s[x]%s Bing RevDNS:\n\t%s\n" % (TC.RED, TC.END, "\n\t".join(error)) )
                                        break

                                    if "No results found for ip:" + target['ipv4'] in bing_res:
                                        break

                                    res = re.findall(r"\<link\>(.*?)\<\/link\>", bing_res)
                                    if res == old_res or not res:
                                        break

                                    else:
                                        old_res = res

                                    for r in res:
                                        if not 'bing.com' in r:
                                            r = re.sub("http[s]?\:\/\/", '', r)
                                            hostnames.append(r.split('/')[0])

                                    nxt += 50

                                dns_cache[target['ipv4']] = list(set(hostnames))
                                binging = False

                        else:                                

                            dns_servers = os.popen("dig soa %s +nostat +nocmd +nocomments | grep -v ';' | grep SOA | cut -f5" % \
                                                    target['ipv4']).read().strip().strip('.')

                            if not dns_servers:                                
                                dns_servers = os.popen("dig ns %s +nostat +nocmd +nocomments | grep -v ';' | grep NS | cut -f5" % \
                                                        target['ipv4']).read().strip().strip('.')
                        
                            for dns_server in dns_servers:
                                if dns_server in dns_cache:
                                    self.output.put("  %s[@]%s DNS AXFR\t: %s (%s) - pulling from cache..." % (TC.PURPLE, TC.END, dns_server, target['hostnames'][0]) )
                                    hostnames = dns_cache[dns_server]
                        
                                axfr = os.popen("dig %s AXFR +nostat +nocmd +nocomments" % dns_server).read()

                                if not 'Transfer failed' in axfr:
                                    pass
                                    # AXFR Placeholder
                                    # hostnames = axfr
                                    #    put LOC records in target['dns_loc'] -  <hostname>:<location>
                                    #    put MX records in target['dns_mx'] -  <hostname>
                                    #    put TXT records in target['dns_txt'] -  <hostname>:<text>
                                    #    put A|CNAME records in queue -  <hostname>:<IP>
                                    #    put NS|SOA records in the dns_servers list if not already there
                                    # dns_cache[dns_server] = hostnames
                                    # forward output of all dns activity to <logfldr>/rawr_DNS_<timestamp>.txt

                                else:
                                    self.output.put("  %s[x]%s RevDNS\t: %s [%s] - Transfer Failed." % (TC.YELLOW, TC.END, dns_server, target['ipv4']))
                            

                        if len(hostnames) > 0:
                            # remove any duplicates from our list of domains...
                            hostnames = list(set(hostnames))
                            self.output.put("  %s[+]%s RevDNS\t: found %s DNS names for %s" %
                                            (TC.CYAN, TC.END, len(hostnames), target['ipv4']))

                            # distribute the load
                            for hostname in hostnames:
                                hn = hostname.strip(': ')
                                if not hn in [target['ipv4'], "https", "http", '']:
                                    if not hn in self.db[task[0]]:
                                        target['is_dns_result'] = True
                                        target['hostnames'] = [hostname.strip()]
                                        self.db[task[0]][hn] = target
                                        q.put((task[0], hn))
                                        self.output.put("  %s[+]%s RevDNS\t: [ %s:%s ] injected into queue." % (TC.CYAN, TC.END, hn, target['port']))

                        else:
                            self.output.put("  %s[x]%s RevDNS\t: found no DNS entries for %s" % (TC.YELLOW, TC.END, target['ipv4']))



                    if not 'url' in target:
                        target['url'] = prefix + hostname + port

                    elif not hostname in target['url']:
                        o = urlparse(target['url'])    
                        target['url'] = target['url'].replace(o.scheme + "://" + o.netloc, prefix + hostname + port)
                        

                    self.output.put("  %s[>]%s Pulling\t: %s" % (TC.GREEN, TC.END, target['url']))
                    try:
                        target['res'] = requests.get(target['url'],
                                                     headers={"user-agent": useragent},
                                                     verify=False,
                                                     timeout=timeout,
                                                     allow_redirects=allow_redir,
                                                     proxies=self.opts.proxy_dict)

                        msg = ["  %s[+]%s Finished" % (TC.CYAN, TC.END), ""]

                    except requests.ConnectionError:
                        try:
                            if '[401]' in target['res']:
                                open('%s/401_failed_auth.lst' % logdir, 'a').write( target['url'] )

                        except:
                            pass

                        msg = ["  %s[x]%s Not found" % (TC.RED, TC.END), ""]

                    except socket.timeout:
                        msg = ["  %s[x]%s Timed out" % (TC.RED, TC.END), ""]

                    except requests.Timeout:
                        msg = ["  %s[x]%s Timed out" % (TC.RED, TC.END), ""]

                    except:
                        error = traceback.format_exc().splitlines()
                        error_msg("\n".join(error))
                        msg = ["  %s[x]%s Error " % (TC.RED, TC.END), ":\n\t%s\n" % ("\n\t".join(error))]

                    if 'res' in target.keys():
                        wordlist = []
                        if not self.opts.json_min:
                            wl = list(set( (target['res'].content).split() ) )
                            for w in wl:
                                if len(w) > 3 and re.search('^[a-zA-Z0-9]+$', w):
                                    wordlist.append(w)                        

                        if self.opts.getoptions:
                            try:
                                res = (requests.options(target['url'],
                                                        headers={"user-agent": useragent},
                                                        verify=False,
                                                        timeout=timeout,
                                                        allow_redirects=allow_redir,
                                                        proxies=self.opts.proxy_dict))

                                if 'allow' in res.headers:
                                    target['options'] = res.headers['allow'].replace(",", " | ")

                                self.output.put("      %s[o]%s pulled OPTIONS: [ %s:%s ]" % (TC.PURPLE, TC.END, hostname, target['port']))

                            except requests.ConnectionError:
                                msg = ["  %s[x]%s Not Found" % (TC.RED, TC.END), ""]

                            except socket.timeout:
                                self.output.put("      %s[x]%s Timed out pulling OPTIONS: [ %s:%s ]" % (TC.RED, TC.END, hostname, target['port']))

                            except requests.Timeout:
                                msg = ["  %s[x]%s Timed out" % (TC.RED, TC.END), ""]

                            except:
                                error = traceback.format_exc().splitlines()
                                error_msg("\n".join(error))
                                self.output.put("      %s[x]%s Failed pulling OPTIONS: [ %s:%s ]\n\t%s\n" %
                                                (TC.RED, TC.END, hostname, target['port'], "\n\t".join(error)))

                        if not self.opts.json_min:
                            target['hist'] = 256
                            if not (self.opts.noss or self.opts.json_min) and 'res' in target.keys():
                                proc = Process(target=screenshot,
                                               args=(target['url'], target['port'],
                                               self.logdir, self.timestamp,
                                               self.scriptpath, self.opts.proxy_dict,
                                               useragent, self.pjs_path,
                                               (self.opts.json or self.opts.json_min),
                                               timeout, use_ghost))
                                proc.start()
                                proc.join()

                                if proc.exitcode == 0:
                                    #target['hist'] = proc[1]
                                    self.output.put("      %s[+]%s Screenshot :   [ %s ]" % (TC.CYAN, TC.END, target['url']))
                                    
                                else:
                                    #target['hist'] = 0
                                    self.output.put("      %s[x]%s Screenshot :   [ %s ] Failed" % (TC.RED, TC.END, target['url']))

                        if self.opts.getcrossdomain:
                            try:
                                res = requests.get("%s/crossdomain.xml" % target['url'],
                                                   headers={"user-agent": useragent},
                                                   verify=False,
                                                   timeout=timeout,
                                                   allow_redirects=allow_redir,
                                                   proxies=self.opts.proxy_dict)

                                if res.status_code == 200:
                                    if not self.opts.json_min:
                                        try:
                                            os.makedirs("cross_domain")
                                            
                                        except:
                                            pass

                                        open("./cross_domain/%s_%s_crossdomain.xml" %
                                             (hostname, target['port']), 'w').write( safe_string(res.content) )
                                        self.output.put("      %s[c]%s Pulled crossdomain.xml : [ %s:%s ]" %
                                                        (TC.PURPLE, TC.END, hostname, target['port']))
                                    target['crossdomain'] = "y"

                            except requests.ConnectionError:
                                msg = ["  %s[x]%s Not found: %s" % (TC.RED, TC.END, hostname), ""]

                            except socket.timeout:
                                self.output.put("      %s[x]%s Timed out pulling crossdomain.xml : [ %s:%s ]" %
                                                (TC.RED, TC.END, hostname, target['port']))

                            except requests.Timeout:
                                msg = ["  %s[x]%s Timed out" % (TC.RED, TC.END), ""]

                            except:
                                error = traceback.format_exc().splitlines()
                                error_msg("\n".join(error))
                                self.output.put("      %s[x]%s Failed pulling crossdomain.xml :\n\t%s\n" %
                                                (TC.RED, TC.END, "\n\t".join(error)) )

                        if self.opts.getrobots:
                            try:
                                res = requests.get("%s/robots.txt" % target['url'],
                                                   headers={"user-agent": useragent},
                                                   verify=False,
                                                   timeout=timeout,
                                                   allow_redirects=allow_redir,
                                                   proxies=self.opts.proxy_dict)

                                if res.status_code == 200 and "llow:" in res.content:
                                    if not self.opts.json_min:
                                        try:
                                            os.makedirs("robots")

                                        except:
                                            pass

                                        open("./robots/%s_%s_robots.txt" %
                                             (hostname, target['port']), 'w').write( safe_string(res.content) )
                                        self.output.put("      %s[r]%s Pulled robots.txt :      [ %s:%s ]" %
                                                        (TC.PURPLE, TC.END, hostname, target['port']))
                                    target['robots'] = "y"

                            except requests.ConnectionError:
                                msg = ["  %s[x]%s Not found" % (TC.RED, TC.END), ""]

                            except socket.timeout:
                                self.output.put("      %s[x]%s Timed out pulling robots.txt :      [ %s:%s ]" %
                                                (TC.RED, TC.END, hostname, target['port']))

                            except requests.Timeout:
                                msg = ["  %s[x]%s Timed out" % (TC.RED, TC.END), ""]

                            except:
                                error = traceback.format_exc().splitlines()
                                error_msg("\n".join(error))
                                self.output.put("      %s[x]%s Failed pulling robots.txt :\n\t%s\n" % (TC.RED, TC.END, "\n\t".join(error)) )

                        if (self.opts.crawl or self.opts.mirror) and not self.opts.json_min:
                            while crawling >= self.opts.spider_thread_limit:
                                time.sleep(0.1)

                            crawling += 1
                            wordlist += crawl(target, self.logdir, self.timestamp, self.opts)
                            crawling -= 1

                        ret = parsedata(task, target, self.timestamp, self.scriptpath, self.opts)

                        if 'wordlist' in target.keys():
                            wordlist += target['wordlist']  # add all suggested passwords to our wordlist
                            del target['wordlist']

                        if not self.opts.json_min:
                            with open('./input_lists/wordlist__%s_%s_%s.lst' % (hostname, target['port'], self.timestamp), 'w') as of:
                                of.write('\n'.join(list(set(wordlist))))

                        wordlist = None

                        if self.opts.json or self.opts.json_min:
                            output.put(ret)

                        if not (self.opts.json_min or target['url'] in outs):
                            outs.append(target['url'])
                            write_to_html(timestamp, ret)
                            write_to_csv(timestamp, ret)

                        # remove redundant / potentially large entries before adding to db
                        for x in [x for x in ('defpass', 'res') if x in target]:
                            del target[x]

                        self.db[task[0]][task[1]] = ret

                        self.output.put("%s  [ %s:%s ]%s" % (msg[0], hostname, target['port'], msg[1]))

                except:
                    error = traceback.format_exc().splitlines()
                    error_msg("\n".join(error))
                    self.output.put("  %s[x]%s Failed : [ %s:%s ]\n\t%s\n" % (TC.RED, TC.END, hostname, target['port'], "\n\t".join(error)))

                self.busy = False

                busy_count = 0
                for t in threads:
                    if t.busy:
                        busy_count += 1

                self.output.put("  %s[i]%s Main queue size [ %s ] - Threads Busy/Total [ %s/%s ]" %
                                (TC.BLUE, TC.END, str(q.qsize()), busy_count, nthreads))

                q.task_done()                


def glob_recurse(f):
    files = []
    for i in glob(f):
        if os.path.isfile(i):
            files.append(os.path.abspath(i))
            
        elif os.path.isdir(i):
            for x in glob_recurse(i + "/*"):
                files.append(os.path.abspath(x))
    
    return files


def safe_string(s):
    try:
        r = str(s)

    except UnicodeEncodeError:
        r = unicode(s).encode('unicode_escape')

    return r


def screenshot(url, port, logdir, timestamp, scriptpath, proxy, useragent, pjs_path, silent, timeout, use_ghost):
    filename = "%s/%s_%s_%s.png" % ("%s/images" % logdir, urlparse(url).netloc, timestamp, port)

    if use_ghost:
        ghost = Ghost(wait_timeout=timeout, user_agent=useragent, show_scrollbars=False, ignore_ssl_errors=True, java_enabled=True, plugins_enabled=True)
        if proxy: 
            ghost.set_proxy('default', proxy['host'], proxy['port'])

        def get_url(url):
            page, res = ghost.open(url)

            if page:
                ghost.capture_to(filename, region=(0,0,640,480))

            else:
                pass # ERROR MSG

            ghost.exit()

        get_url(url)

    else:
        if not os.path.exists(filename):  # the picture hasn't already been taken
            lp = "/dev/null"  # not logging (json, json-min)
            if not silent:
                lp = "%s/rawr_%s.log" % (logdir, timestamp)

            with open(lp, 'ab') as log_pipe:
                start = datetime.datetime.now()
                cmd = [pjs_path]

                if proxy:
                    cmd.append("--proxy=%s" % proxy['http'])  # Same ip:port is used for both http and https.

                cmd += "--web-security=no", "--ignore-ssl-errors=yes", "--ssl-protocol=any",\
                       (scriptpath + "/data/screenshot.js"), url, filename, useragent, str(ss_delay)
                       
                try:
                    process = subprocess.Popen(cmd, stdout=log_pipe, stderr=log_pipe)

                    while process.poll() is None:
                        time.sleep(0.1)
                        now = datetime.datetime.now()
                        if (now - start).seconds > timeout + 1:
                            try:
                                sig = getattr(signal, 'SIGKILL', signal.SIGTERM)
                                os.kill(process.pid, sig)
                                os.waitpid(-1, os.WNOHANG)
    
                            except:
                                pass
                            
                            return (False, ' Timed Out.')

                except:
                    return (False, "\n\t\t".join(traceback.format_exc().splitlines()))

        if not os.path.isfile(filename):
            shutil.copy(scriptpath + "/data/error.png", filename)    
            return(False, '.png not created')

        elif os.stat(filename).st_size > 0:
            try:  # histogram time!
                rgb, c = (0, 0, 0), 0
                img = Image.open(filename).resize((150, 150))
                for x in xrange(img.size[0]):
                    for y in xrange(img.size[1]):
                        t = img.load()[x, y]
                        tuple(map(sum,zip(rgb,t)))
                        c += 1

                hsv = colorsys.rgb_to_hsv( tuple((x / c) for x in rgb) )
                return (True, hsv[2])

            except:  # histogram failed
                return (True, 0)

        else:
            shutil.copy(scriptpath + "/data/error.png", filename)    
            return(False, '0 byte file. [Deleted]')


def crawl(target, logdir, timestamp, opts):  # Our Spidering function.
    output.put("      %s[>]%s Spidering  :     [ %s ]" % (TC.GREEN, TC.END, target['url']))
    from PIL.ExifTags import TAGS

    def recurse(url_t1, urls_t2, tabs, depth):
        url_t1 = url_t1.strip('"/\; ()')

        for url_t2 in urls_t2:
            url_t2 = url_t2.strip('"/\; ()').replace("/#", "")

            if opts.verbose:
                output.put("      %s[i]%s [%s] threads %s/%s - depth %s/%s - sec %d/%s - urls %s/%s" %
                           (TC.BLUE, TC.END, target['url'], crawling, opts.spider_thread_limit, depth, opts.spider_depth,
                            (datetime.datetime.now() - time_start).total_seconds(),
                            opts.spider_timeout, len(list(set(urls_visited))), opts.spider_url_limit))

            if len(list(set(urls_visited))) > opts.spider_url_limit:
                if opts.verbose:
                    output.put("      %s[!]%s Spidering stopped at depth - %s:   [ %s ] - URL limit reached" %
                               (TC.YELLOW, TC.END, str(depth), target['url']))

                break

            elif (datetime.datetime.now() - time_start).seconds > opts.spider_timeout:
                if opts.verbose:
                    output.put("      %s[!]%s Spidering stopped at depth - %s:   [ %s ] - Timed out" %
                               (TC.YELLOW, TC.END, str(depth), target['url']))

                break

            if not url_t2 in ("https://ssl", "http://www", "http://", "http://-", "http:", "https:"):  # ga junk
                coll.append((url_t1.replace(":", "-"), url_t2.replace(":", "-")))

                if not (url_t2 in urls_visited or (opts.spider_url_blacklist and (url_t2 in url_blacklist))):
                    with open('%s/diagrams/links_%s_%s__%s.txt' % (logdir, hname, target['port'], timestamp), 'a') as of:
                        of.write("%s%s\n" % (tabs, safe_string(url_t2)))

                if not (url_t2 in urls_visited or (opts.spider_url_blacklist and (url_t2 in url_blacklist))):
                    try:
                        p = urlparse(url_t2)
                        urls_visited.append(url_t2)

                        if opts.spider_follow_subdomains:
                            url_t2_hn = ".".join(p.netloc.split(".")[-2:])

                        else:
                            url_t2_hn = p.netloc

                        if url_t2_hn in url_t1 or opts.alt_domains and url_t2_hn in opts.alt_domains.split(','):
                            urls_t3 = []
                            try:
                                doc_f = '%s/meta/%s_%s_%s_findings.csv' % (logdir, hname, target['port'], timestamp)
                                dat = session.get(url_t2,
                                                  headers={"user-agent": useragent, "referer": url_t1},
                                                  verify=False,
                                                  timeout=opts.spider_url_timeout,
                                                  allow_redirects=False,
                                                  proxies=opts.proxy_dict)

                                if dat.status_code == 201:
                                    open('%s/201_pages.lst' % logdir, 'a').write(url_t2 + '\n')

                                elif dat.status_code == (300, 301, 302, 303, 305, 306, 307, 308):
                                    if "location" in dat.headers.keys():
                                        for l in dat.headers['location']:
                                            if url_t2_hn in l:
                                                urls_t3.append(l)

                                elif dat.status_code == 401:
                                    open('%s/401_failed_auth.lst' % logdir, 'a').write(url_t2 + '\n')

                                elif dat.content and dat.status_code != 404:
                                    l = list(set( (target['res'].content).split() ) )
                                    for w in l:
                                        if len(w) > 3 and re.search('^[a-zA-Z0-9]+$', w):
                                            wl.append(w)  

                                    page = p.path.split('/')[-1]
                                    if opts.mirror:
                                        fpath = '%s/mirrored_sites/%s_%s%s' % (logdir, hname, target['port'], p.path.replace(page, ''))
                                        fn = '%s/mirrored_sites/%s_%s%s' % (logdir, hname, target['port'], p.path)

                                        try:
                                            os.makedirs(fpath)

                                        except:
                                            pass

                                        with open(fn, 'wb') as wf:
                                            for chunk in dat.iter_content(200):
                                                wf.write(chunk)

                                    else:
                                        fpath = '%s/meta/%s_%s_files' % (logdir, hname, target['port'])
                                        fn = '%s/%s' % (fpath, page)

                                    ext = p.path.split(".")[-1].lower()

                                    # parse for meta
                                    if ext in DOC_TYPES and url_t2 not in target['docs']:
                                        if not opts.mirror:
                                            try:
                                                os.makedirs(fpath)

                                            except:
                                                pass

                                            fpath = '%s/meta/%s_%s_files' % (logdir, hname, target['port'])
                                            fn = '%s/%s' % (fpath, page)

                                            with open(fn, 'wb') as wf:
                                                for chunk in dat.iter_content(200):
                                                    wf.write(chunk)

                                        target['docs'].append(str(url_t2))

                                        with open(doc_f, 'a') as ofn:
                                            ofn.write('DOC,%s\n' % safe_string(url_t2))

                                        try:                                        
                                            report_fname = '%s/meta_report_%s.html' % (logdir, timestamp)
                                            ret = meta_parser.parse(fn)
                                            meta_parser.add_to_report(fn, report_fname, ret, url_t2)
                                            if ret:
                                                output.put("          %s[#]%s Meta logged: %s" % (TC.PURPLE, TC.END, os.path.basename(fn)) )

                                            try: os.system('rm -rf ./tmp')
                                            except: pass

                                        except:
                                            e = traceback.format_exc().splitlines()
                                            print(" [spider] processing document:\n\t%s\n\t%s" % (url_t2, e))

                                    elif ext in OTHER_TYPES:
                                        try:
                                            os.makedirs(fpath)

                                        except:
                                            pass

                                        with open(doc_f, 'a') as ofn:
                                            ofn.write('OTHER,%s\n' % safe_string(url_t2))


                                    for u in list(set(re.findall(URL_REGEX, dat.content, re.I))):
                                        urls_t3.append(u.split('"')[0].split("'")[0].split(
                                                       "<")[0].split("--")[0].rstrip('%)/.'))  # supplement the regex

                                    if dat.content.rstrip():
                                        try:  # parse the html for tags w/ href or source
                                            cxt = html.fromstring(str(dat.content))
                                            for el in cxt.iter():
                                                try:
                                                    if str(el.tag).strip().lower() in ['link', 'a', 'script', 'iframe',
                                                                  'applet', 'area', 'object', 'embed', 'form']:
                                                        for i, v in el.items():
                                                            if i in ("src", "href"):
                                                                if "mailto" in v:
                                                                    x = safe_string(v.split(":")[1])
                                                                    try:
                                                                        if not x in target['email_addresses']:                                    
                                                                            target['email_addresses'].append(x)

                                                                    except: target['email_addresses'] = [x]

                                                                else:
                                                                    if not v.split("//")[0] in ("http:", "https:"):
                                                                        v = v.replace("../", '')
                                                                        if not v.startswith("/"):
                                                                            v = "/" + v

                                                                        v = p.scheme + "://" + p.netloc + v
                                                                        urls_t3.append(v)

                                                except:
                                                    #pass
                                                    e = traceback.format_exc().splitlines()
                                                    error_msg(" [spider] parsing HTML element:\n\t%s\n\t%s" %
                                                              (url_t2, e))

                                        except:
                                            pass
                                            #e = traceback.format_exc().splitlines()[-1]
                                            #error_msg(" [spider] parsing HTML from:\n\t%s\n\t%s" % (url_t2, e))

                                    urls_t3 = list(set(urls_t3))

                                    if len(urls_t3) > 0:
                                        if not (len(list(set(urls_visited))) > opts.spider_url_limit
                                                or depth >= opts.spider_depth
                                                or (datetime.datetime.now() - time_start).total_seconds() > opts.spider_timeout):
                                            if opts.spider_breadth_first:  # Not a 'tree' until we move to nosqlite
                                                urls_to_crawl.put([url_t2, urls_t3, "\t", depth + 1])

                                            else:
                                                recurse(url_t2, urls_t3, tabs + "\t", depth + 1)

                            except:
                                #pass
                                e = traceback.format_exc().splitlines()
                                error_msg(" [spider] pulling [ %s ]:\n\t%s" % (target['url'], e))

                    except:
                        pass  # problem parsing the url

    if opts.spider_url_blacklist:
        if os.path.isfile(opts.spider_url_blacklist):
            url_blacklist = open(opts.spider_url_blacklist).read().split('\n')
            output.put("        %s[i]%s Spidering - blacklisting %s urls." % (TC.BLUE, TC.END, len(url_blacklist)-1) )

        else:
            output.put("        %s[i]%s Spidering - unable to find blacklist file - " % (TC.BLUE, TC.END, opts.spider_url_blacklist) )

    coll, urls_visited, target['docs'], target['exif_docs'] = [], [], [], []
    hname = urlparse(target['url']).netloc
    wl = []
    time_start = datetime.datetime.now()
    session = requests.Session()

    if not os.path.exists("diagrams"):
        try:
            os.makedirs("diagrams")

        except:
            pass

    if opts.spider_breadth_first:
        urls_to_crawl = Queue()
        urls_to_crawl.put([target['url'], [target['url']], "\t", 1])
        while not urls_to_crawl.empty():
                x, y, t, d = urls_to_crawl.get()
                recurse(x, y, t, d)

        urls_to_crawl = None

    else:  # length first
        recurse(target['url'], [target['url']], "\t", 1)

    session = None
    target['doc_count'] = len(target['docs'])

    if len(coll) < 2:
        output.put("      %s[+]%s Finished spider: [ %s ] - no links, skipping graph..." % (TC.CYAN, TC.END, target['url']) )

    else:
        try: 
            output.put("      %s[+]%s Finished spider: [ %s ] - building graph..." % (TC.CYAN, TC.END, target['url']))

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
                output.put("      %s[i]%s Processing data for [ %s ]:   %s nodes / %s unique" %
                           (TC.BLUE, TC.END, target['url'], len(c), len(list(set(c)))))

            for node in c[:50]:
                if node == target['url'].replace(':', '-'):
                    gr.add_node(node, root=True, shape=ROOT_NODE_SHAPE, color=ROOT_NODE_COLOR)

                elif not urlparse(target['url']).netloc in node:
                    gr.add_node(node, shape=EXTERNAL_NODE_SHAPE, color=EXTERNAL_NODE_COLOR)

                else:
                    gr.add_node(node)

            if opts.verbose:
                output.put("      %s[i]%s Processing colls for [ %s ]:   %s colls" % (TC.BLUE, TC.END, target['url'], len(coll)) )

            for x, y in [z for z in coll if z[0] != z[1]]:
                gr.add_edge((x, y))

            # Draw as PNG
            gr.layout(prog=LAYOUT_TYPE)
            # will get a warning if the graph is too large - not fatal
            f = '%s/diagrams/diagram_%s_%s__%s.png' % (logdir, urlparse(target['url']).netloc, target['port'], timestamp)

            if opts.verbose:
                output.put("      %s[i]%s Drawing diagram for [ %s ]: %s" % (TC.BLUE, TC.END, target['url'], f) )

            gr.draw(f)
            target['diagram'] = f

        except:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            output.put("\n    %s[!]%s Unable to create site chart: [ %s ]\n\t%s\n" % (TC.YELLOW, TC.END, target['url'], "\n\t".join(error)))

    return wl


def parsedata(task, target, timestamp, scriptpath, opts):  # Takes raw site response and parses it.
    for i, v in target.items():
        target[i] = target[str(i)]

    # identify country if possible
    try:
        with open("%s/%s" % (scriptpath, IP_TO_COUNTRY)) as f:
            for c, l in enumerate(f):
                if l != "" and not "#" in l:
                    l = l.replace('"', '').split(',')
                    if int(l[1]) > target['ipnum'] > int(l[0]):
                        target['country'] = "[%s]-%s" % (l[4], l[6].strip('\n'))
                        break

    except:
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        output.put("  %s[!]%s IPtoCountry parse error:\n\t%s\n" % (TC.YELLOW, TC.END, "\n\t".join(error)) )

    if 'res' in target.keys():
        # eat cookie now....omnomnom
        if len(target['res'].cookies) > 0:
            try:
                os.mkdir("cookies")

            except: pass

            with open("./cookies/%s_%s.txt" % (urlparse(target['url']).netloc, target['port']), 'w') as of:
                of.write(str(target['res'].cookies))

            target['cookies'] = len(target['res'].cookies)
            target['content-type'] = re.findall("charset=(.*)[\s|\r]", str(str(target['res'].cookies)))

        if not 'content-type' in target.keys():
            try: target['content-type'] = re.findall("charset=(.*)[\s|\r]", str(target['res'].headers['content-type']))
            except: pass

        target['endurl'] = target['res'].url

        for h in target['res'].headers:
            target[h] = target['res'].headers[h]

        target['encoding'] = target['res'].encoding
        target['history'] = [h.url for h in target['res'].history]
        target['returncode'] = str(target['res'].status_code)

        # Run through any user-defined regex filters.
        #  *** If a field isn't present in 'flist' (in the settings section), it won't be added at this time.
        parsermods = []
        for field, regxp, modtype, d in modules:
            try:
                # MODTYPE_CONTENT - returns all matches, seperates by ';'
                if modtype == 0:
                    for i in (re.findall(regxp, target['res'].content, re.I)):
                        if field == "comments":
                            i = i.replace('<', '&lt;')

                        elif field == "urls":
                            i = i.split("'")[0].rstrip(')/.')

                        try:
                            target[field].append(str(i))

                        except:
                            target[field] = [str(i)]

                # MODTYPE_TRUEFALSE - returns 'True' or 'False' based on regxp
                elif modtype == 1:
                    if len(re.findall(regxp, target['res'].content, re.I)) > 0:
                        target[field] = "True"

                    else:
                        target[field] = "False"

                # MODTYPE_COUNT - counts the number of returned matches
                elif modtype == 2:
                    target[field] = len(re.findall(regxp, target['res'].content, re.I))

                # PARSER modules
                elif modtype in [3, 4, 5]:
                    if type(regxp) == tuple and len(regxp) == 3:
                        parsermods.append((field, regxp, modtype))

                else:
                    output.put("  %s[!]%s skipping %s - invalid modtype" % (TC.YELLOW, TC.END, field) )

            except:
                error = traceback.format_exc().splitlines()
                error_msg("\n".join(error))
                output.put("  %s[!]%s skipping module '%s' :\n\t%s\n" % (TC.YELLOW, TC.END, field, "\n\t".join(error)))

        # parse the html for different element types
        if target['res'].content:
            try:
                cxt = html.fromstring(str(target['res'].content))
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
                                output.put("  %s[!]%s skipping module '%s':\n\t%s\n" % (TC.YELLOW, TC.END, n, "\n\t".join(error)))

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
                                        x = safe_string(v.split(":")[1])
                                        try:
                                            if not x in target['email_addresses']:                                    
                                                target['email_addresses'].append(x)

                                        except: target['email_addresses'] = [x]

                                    else:
                                        try: target['urls'].append(safe_string(v))
                                        except: target['urls'] = [safe_string(v)]

                        elif tag == "input":
                            for i, v in items:
                                if v.lower == "password":
                                    try: target['passwordFields'].append(html.tostring(safe_string(el)))
                                    except: target['passwordFields'] = [html.tostring(safe_string(el))]

                            target['input'] = len(items)

                        elif tag in ('iframe', 'applet', 'object', 'embed', 'form'):
                            target[tag] = len(items)

                    except:
                        error = '\n\t\t'.join( traceback.format_exc().splitlines() )
                        error_msg(" parsing HTML element [ %s ]:\n\t%s" % (target['url'], error) )
                        if opts.verbose:
                            output.put("  %s[!]%s Error parsing HTML element:\n\t%s\n" % (TC.YELLOW, TC.END, error) )

            except:
                error = '\n\t\t'.join( traceback.format_exc().splitlines() )
                error_msg(" parsing HTML element [ %s ]:\n\t%s" % (target['url'], error) )
                if opts.verbose:
                    output.put("  %s[!]%s Error parsing HTML from:\n\t%s\n" % (TC.YELLOW, TC.END, error) )

            finally:
                cxt = None

        # grab all the headers
        for header in target['res'].headers:
            target[header.lower()] = target['res'].headers[header]

        # check CPE for matches in the DPE Database
        if opts.defpass and "cpe" in target.keys():
            target['cve'], target['defpass'], target['wordlist'] = [], [], []
            dpe = etree.parse("%s/%s" % (scriptpath, DPE_FILE) )

            for el_model in dpe.xpath("//*[@cpe]"):
                try:
                    if el_model.attrib["cpe"] == target["cpe"]:
                        target['type'] = el_model.attrib["type"]
                        target['dpe_description'] = el_model.attrib["description"]

                        for el in el_model.getchildren():
                            if el.tag.endswith("info") and el.attrib["cve"]:
                                target['cve'] = el.attrib["cve"]

                            elif el.tag.endswith("credential"):
                                if not 'printed on' in el.attrib["password"]:
                                    target['wordlist'].append( el.attrib["password"] )

                                un = 'blank'
                                if el.attrib["username"]:
                                    un = el.attrib["username"]
                                    target['usernames'].append( un )

                                target['defpass'].append( un + ":" + el.attrib["password"] )

                        break

                except:
                    error = traceback.format_exc().splitlines()
                    error_msg("\n".join(error))
                    output.put("\n  %s[!]%s Error parsing dpe_db.xml\n\t%s\n" % (TC.YELLOW, TC.END, "\n\t".join(error)) )

    if "service_tunnel" in target:
        if target['service_tunnel'] == 'ssl':
            if not 'ssl-cert' in target and 'returncode' in target:
                # ^ hosts were loaded by a file that didn't contain SSL info
                output.put("  %s[>]%s Pulling SSL cert for  %s" % (TC.GREEN, TC.END, target['url']))
    
                import ssl
                cert = None
                try:
                    cert = ssl.get_server_certificate((target['hostnames'][0], int(target['port'])),
                                                      ssl_version=ssl.PROTOCOL_TLSv1)
    
                except:
                    try:
                        cert = ssl.get_server_certificate((target['hostnames'][0], int(target['port'])))
    
                    except: pass   # get an error in here!
    
                finally:
                    if not opts.json_min:
                        try:
                            os.mkdir("ssl_certs")
            
                        except: pass
            
                try:
                    if cert:
                        certfile = "./ssl_certs/%s_%s.pem" % (urlparse(target['url']).netloc, target['port'])
                        open(certfile, 'w').write(cert)
                
                        proc = subprocess.Popen(['openssl', 'x509', '-in', certfile, '-inform', 'PEM', '-text'], stdout=subprocess.PIPE)
                        target['ssl-cert'] = proc.stdout.read()
                        notbefore = ""
                        notafter = ""
                        for line in target['ssl-cert'].split('\n'):
                            try:
                                if "issuer" in line.lower():
                                    target['ssl_cert-issuer'] = line.split(": ")[1]
        
                                elif "subject" in line.lower() and not 'ssl_cert-subject' in target.keys():
                                    target['ssl_cert-subject'] = line.split(": ")[1]
        
                                    if "*" in line.split(": ")[1]:
                                        subject = line.split(": ")[1].split("*")[1]
        
                                    else:
                                        subject = line.split(": ")[1]
        
                                    if subject in target['hostnames']:
                                        target['ssl_cert-verified'] = "yes"
        
                                elif "md5" in line.lower() and not 'ssl_cert-md5' in target.keys():
                                    target['ssl_cert-md5'] = line.split(": ")[1].replace(" ", '')
        
                                elif "sha-1" in line.lower() and not 'ssl_cert-sha-1' in target.keys():
                                    target['ssl_cert-sha-1'] = line.split(": ")[1].replace(" ", '')
        
                                elif "Signature Algorithm" in line.lower() and not 'ssl_cert-keyalg' in target.keys():
                                    target['ssl_cert-keyalg'] = "%s" % line.split(": ")[1]
                                    # need to take another look at this one.  not seeing it atm
        
                                elif "not before" in line.lower():
                                    notbefore = line.split(": ")[1].strip()
                                    target['ssl_cert-notbefore'] = notbefore
        
                                elif "not after" in line.lower():
                                    notafter = line.split(": ")[1].strip()
                                    target['ssl_cert-notafter'] = notafter
                                    
                            except: pass
    
                        try:
                            notbefore =  datetime.datetime.strptime(str(notbefore), '%b %d %H:%M:%S %Y %Z') # Apr 23 12:16:09 2014 GMT
                            notafter =  datetime.datetime.strptime(str(notafter), '%b %d %H:%M:%S %Y %Z')
                            vdays = (notafter - notbefore).days
                            if datetime.datetime.now() > notafter:
                                daysleft = "EXPIRED"
    
                            else:
                                daysleft = (notafter - datetime.datetime.now()).days
    
                        except:
                            vdays = "unk"
                            daysleft = "unk"
    
                        target['ssl_cert-validityperiod'] = vdays
                        target['ssl_cert-daysleft'] = daysleft
    
                except:
                    error = traceback.format_exc().splitlines()
                    error_msg("\n".join(error))
                    output.put("\n  %s[!]%s Error parsing cert:\n\t%s\n" % (TC.YELLOW, TC.END, "\n\t".join(error)) )
        
                target['ssl-cert'] = 'true'
                
            # Parse cert and write to file
            elif not opts.json_min and 'ssl-cert' in target.keys():
                try:
                    os.mkdir("ssl_certs")
    
                except:
                    pass
    
                open("./ssl_certs/%s_%s.cert" %
                     (urlparse(target['url']).netloc, target['port']), 'w').write(target['ssl-cert'])

                target['ssl-cert'] = 'true'

    return target


def write_to_csv(timestamp, target):
    x = [" "] * len(flist.split(","))

    if not os.path.isfile("rawr_%s_serverinfo.csv" % timestamp):
        open("rawr_%s_serverinfo.csv" % timestamp, 'w').write(flist)

    for i, v in target.items():
        if i.lower() in flist.lower().split(', '):  # matching up the columns with our values
            x[flist.lower().split(", ").index(i.lower())] = re.sub('[\n\r,]', '', safe_string(v).replace('"', '&quot;'))

    try:
        open("rawr_%s_serverinfo.csv" % timestamp, 'a').write('\n"%s"' % (str('","'.join(x))))

    except:
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        output.put("\n  %s[!]%s Unable to write .csv:\n\t%s\n" % (TC.YELLOW, TC.END, "\n\t".join(error)) )


def write_to_html(timestamp, target):
    with open('sec_headers_%s.html' % timestamp, 'a') as of:
        of.write('<tr><td>%s</td>' % target['url'])
        for header, chks, undef in SECURITY_HEADERS:
            found = False
            if header.lower() in target:
                hdrString = target[header.lower()]
                for chk in chks:
                    if chk[0] in hdrString.lower():
                        of.write(chk[1].replace('<<>>', hdrString))
                        found = True
                        break

            if not found:
                of.write(undef)

        of.write('</tr>')    

    x = [" "] * len(flist.split(","))
    for i, v in target.items():    
        if i.lower() in flist.lower().split(', '):
            try:
                x[flist.lower().split(", ").index(i.lower())] = re.sub('[\n\r,]', '', safe_string(v))

            except:
                error_msg("\n".join(traceback.format_exc().splitlines()[-3:]))

    try:
        with open('index_%s.html' % timestamp, 'a') as of:
            of.write("\n" + str(target['hist']) + ", " + str(','.join(x)))

    except:
        error = traceback.format_exc().splitlines()
        error_msg("\n".join(error))
        output.put("\n  %s[!]%s Unable to write .html:\n\t%s\n" % (TC.YELLOW, TC.END, "\n\t".join(error)) )


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

                elif line.strip() != "":
                    target = {}
                    target['hostnames'] = []
                    line = line.strip("\n").replace('"', '').split(',')
                    for header in headers:
                        if header == "host":
                            target['ipv4'] = line[headers.index(header)]

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
                        field = ', '.join([s for s in ('host', 'port', 'name', 'info') if not s in headers])
                        print("      %s[!]%s Parse Error: missing required field(s): %s" % (TC.YELLOW, TC.END, field) )
                        break

            except:
                error = traceback.format_exc().splitlines()
                error_msg("\n".join(error))
                print("      %s[!]%s Parse Error:\n\t%s\n" % (TC.YELLOW, TC.END, "\n\t".join(error)) )

    return targets


def parse_qualys_port_service_csv(filename):
    targets = []
    body = False
    with open(filename) as r:
        try:
            for line in r:
                if line.startswith('"IP"'):
                    body = True
                    continue

                if body and line.strip() != "":
                    target = {}
                    target['ipv4'], hn, sv, target['protocol'], target['port'], sn, df, du = line.replace('"', '').split(',')
                    target['hostnames'] = [hn]
                    target['service_version'] = "%s %s" % (sv, sn)
                    if any(s in sn.lower() for s in ["ssl", "https", "tls", "www"]):
                        target['service_name'] = 'https'

                    else:
                        target['service_name'] = 'http'

                    targets.append(target)

        except:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      %s[!]%s Parse Error:\n\t%s\n" % (TC.YELLOW, TC.END, "\n\t".join(error)) )

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
            print("      %s[!]%s Parse Error:\n\t%s\n" % (TC.YELLOW, TC.END, "\n\t".join(error)) )

    return targets


def parse_nexpose_xml(r):     # need a scan of a server using SSL!
    targets = []
    for node in r.xpath("//NexposeReport/nodes/node"):
        try:
            for endpoint in node.xpath("endpoints/endpoint"):
                target = {}

                target['ipv4'] = node.attrib['address']

                target['hostnames'] = list(set([x.lower() for x in node.xpath("names/name/text()")]))

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
            print("      %s[!]%s Parse Error:\n\t%s\n" % (TC.YELLOW, TC.END, "\n\t".join(error)) )

    return targets


def parse_nexpose_simple_xml(r):     # need a scan of a server using SSL!
    targets = []
    for node in r.xpath("//NeXposeSimpleXML/devices/device"):
        try:
            for service in node.xpath("services/service"):
                target = {}
                target['ipv4'] = node.attrib['address']

                target['hostnames'] = []  # DNS? HOSTNAME?

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
            print("      %s[!]%s Parse Error:\n\t%s\n" % (TC.YELLOW, TC.END, "\n\t".join(error)) )

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
                                        target['ssl_cert-issuer'] = item.split('\t')[1]

                            if "SUBJECT NAME" in line:
                                for item in line.split('\n'):
                                    if "commonName" in item:
                                        target['ssl_cert-subject'] = item.split('\t')[1]

                            elif "commonName" in line and not 'ssl_common-name' in target.keys():
                                target['ssl_common-name'] = line.split("\t")[1].replace(" ", '')

                            elif "organizationName" in line and not 'ssl_organization' in target.keys():
                                target['ssl_organization'] = "%s" % line.split("\t")[1].replace('\n', '')

                            elif "Public Key Algorithm" in line and not 'ssl_cert-keyalg' in target.keys():
                                target['ssl_cert-keyalg'] = "%s" % line.split("\t")[1].replace('\n', '')

                            elif "Signature Algorithm" in line and not 'ssl_cert-sigalg' in target.keys():
                                target['ssl_cert-sigalg'] = "%s" % line.split("\t")[1].replace('\n', '')

                            elif "RSA Public Key" in line and not 'ssl_keylength' in target.keys():
                                target['ssl_keylength'] = "%s" % line.split("\t")[1].replace('\n', '')

                            elif "Valid From" in line:
                                notbefore = line.split("\t")[1].strip()
                                target['ssl_cert-notbefore'] = notbefore

                            elif "Valid Till" in line:
                                notafter = line.split("\t")[1].strip()
                                target['ssl_cert-notafter'] = notafter

                        try:
                            notbefore =  datetime.datetime.strptime(notbefore, '%b %d %H:%M:%S %Y %Z')
                            notafter =  datetime.datetime.strptime(notafter, '%b %d %H:%M:%S %Y %Z')
                            vdays = (notafter - notbefore).days
                            if datetime.datetime.now() > notafter:
                                daysleft = "EXPIRED"

                            else:
                                daysleft = (notafter - datetime.datetime.now()).days

                            target['ssl_cert-validityperiod'] = vdays
                            target['ssl_cert-daysleft'] = daysleft

                        except:
                            pass

                    else:
                        target['service_name'] = 'http'

                    targets.append(target)

        except:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      %s[!]%s Parse Error:\n\t%s\n" % (TC.YELLOW, TC.END, "\n\t".join(error)) )

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
                            target['ssl_tunnel-ciphers'] = list(node.xpath(
                                                                "ReportItem[@port='" + str(target['port']) +
                                                                "' and @pluginName='SSL / TLS Versions " +
                                                                "Supported']/plugin_output" +
                                                                "/text()")[0].split('\n')[1].split())[3].strip('.')
                            target["ssl_tunnel-weakest"] = target['ssl_tunnel-ciphers'].split('/')[0]
                            target['ssl_cert-issuer'] = target['ssl-cert'].split(
                                "Issuer Name")[0].split("Common Name:")[1].split('\n\n')[0].split('\n')[0].strip()
                            target['ssl_cert-subject'] = target['ssl-cert'].split(
                                "Serial Number")[0].split("Common Name:")[1].split('\n\n')[0].split('\n')[0].strip()

                            for line in target['ssl-cert'].split("\n\n"):
                                if "Organization" in line and not 'ssl_organization' in target.keys():
                                    target['ssl_organization'] = "%s" % line.split('\n')[0].split(": ")[1]

                                elif "Signature Algorithm" in line:
                                    target['ssl_cert-keyalg'] = "%s" % line.split(": ")[1]

                                elif "Key Length" in line and not 'ssl_keylength' in target.keys():
                                    target['ssl_keylength'] = "%s" % line.split('\n')[1].split(": ")[1]

                                elif "Not Valid Before" in line:
                                    notbefore = line.split('\n')[0].split(": ")[1].strip('\n\n')
                                    notafter = line.split('\n')[1].split(": ")[1].strip('\n\n')
                                    target['ssl_cert-notbefore'] = notbefore
                                    target['ssl_cert-notafter'] = notafter

                            try:
                                notbefore =  datetime.datetime.strptime(notbefore, '%b %d %H:%M:%S %Y %Z')
                                notafter =  datetime.datetime.strptime(notafter, '%b %d %H:%M:%S %Y %Z')
                                vdays = (notafter - notbefore).days
                                if datetime.datetime.now() > notafter:
                                    daysleft = "EXPIRED"

                                else:
                                    daysleft = (notafter - datetime.datetime.now()).days

                                target['ssl_cert-validityperiod'] = vdays
                                target['ssl_cert-daysleft'] = daysleft

                            except:
                                pass

                    else:
                        target['service_name'] = item.attrib['svc_name']

                    targets.append(target)

        except:
            error = traceback.format_exc().splitlines()
            error_msg("\n".join(error))
            print("      %s[!]%s Parse Error:\n\t%s\n" % (TC.YELLOW, TC.END, "\n\t".join(error)) )

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

                try:
                    target['cpe'] = str(el_svc.xpath("cpe/text()")[0])

                except: pass

                if target["service_version"] != []:
                    target["service_version"] = ' '.join(target["service_version"])

                for el_scpt in el_port.xpath("script"):
                    if el_scpt.attrib['id'] == "ssl-cert":
                        target['service_name'] = 'https'
                        target['ssl-cert'] = el_scpt.attrib['output']
                        for line in target['ssl-cert'].split('\n'):
                            if "issuer" in line.lower():
                                target['ssl_cert-issuer'] = line.split(": ")[1]

                            elif "subject" in line.lower() and not 'ssl_cert-subject' in target.keys():
                                target['ssl_cert-subject'] = line.split(": ")[1]

                                if "*" in line.split(": ")[1]:
                                    subject = line.split(": ")[1].split("*")[1]

                                else:
                                    subject = line.split(": ")[1]

                                if subject in target['hostnames']:
                                    target['ssl_cert-verified'] = "yes"

                            elif "md5" in line.lower() and not 'ssl_cert-md5' in target.keys():
                                target['ssl_cert-md5'] = line.split(": ")[1].replace(" ", '')

                            elif "sha-1" in line.lower() and not 'ssl_cert-sha-1' in target.keys():
                                target['ssl_cert-sha-1'] = line.split(": ")[1].replace(" ", '')

                            elif "algorithm" in line.lower() and not 'ssl_cert-keyalg' in target.keys():
                                target['ssl_cert-keyalg'] = "%s" % line.split(": ")[1]
                                # need to take another look at this one.  no seeing it atm

                            elif "not valid before" in line.lower():
                                notbefore = line.split(": ")[1].strip()
                                target['ssl_cert-notbefore'] = notbefore

                            elif "not valid after" in line.lower():
                                notafter = line.split(": ")[1].strip()
                                target['ssl_cert-notafter'] = notafter

                        try:
                            notbefore =  datetime.datetime.strptime(str(notbefore).split("+")[0], '%Y-%m-%d %H:%M:%S')
                            notafter =  datetime.datetime.strptime(str(notafter).split("+")[0], '%Y-%m-%d %H:%M:%S')

                        except:  # Different format
                            notbefore =  datetime.datetime.strptime(str(notbefore).split("+")[0], '%Y-%m-%dT%H:%M:%S')
                            notafter =  datetime.datetime.strptime(str(notafter).split("+")[0], '%Y-%m-%dT%H:%M:%S')

                        vdays = (notafter - notbefore).days
                        if datetime.datetime.now() > notafter:
                            daysleft = "EXPIRED"

                        else:
                            daysleft = (notafter - datetime.datetime.now()).days

                        target['ssl_cert-validityperiod'] = vdays
                        target['ssl_cert-daysleft'] = daysleft

                    if el_scpt.attrib['id'] == "ssl-enum-ciphers":
                        target["ssl_tunnel-ciphers"] = el_scpt.attrib['output'].replace("\n", ";")
                        target["ssl_tunnel-weakest"] = el_scpt.attrib['output'][-1].strip('\n ')

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
            print("      %s[!]%s Parse Error:\n\t%s\n" % (TC.YELLOW, TC.END, "\n\t".join(error)) )
    
    return targets


def update(pjs_path, scriptpath, force, use_ghost):
    import urllib2
    os.chdir(scriptpath)

    print("  %s[>]%s Updating...  \n" % (TC.GREEN, TC.END) )

    # nmap
    if not (inpath("nmap") or inpath("nmap.exe")):
        print("  %s[i]%s NMap not found in $PATH.  You'll need to install it to use RAWR.  \n" % (TC.CYAN, TC.END) )

    else:
        proc = subprocess.Popen(['nmap', '-V'], stdout=subprocess.PIPE)
        ver = proc.stdout.read().split(' ')[2]
        if int(ver.split('.')[0]) < 6:  # 6.00 is when ssl_num_ciphers.nse was added.
            print("  %s[!]%s NMap %s found, but versions prior to 6.00 won't return all SSL data.\n" % (TC.YELLOW, TC.END, ver) )

        else:
            print("  %s[i]%s NMap %s found\n" % (TC.CYAN, TC.END, ver) )

    #PhantomJS
    if not use_ghost:
        try:
            proc = subprocess.Popen([pjs_path, '-v'], stdout=subprocess.PIPE)
            pjs_curr = re.sub('[\n\r]', '', proc.stdout.read())

        except: pjs_curr = 0

        if force or (PJS_VER > pjs_curr):
            if pjs_curr != 0 and (PJS_VER > pjs_curr):
                choice = raw_input("\n  %s[i]%s phantomJS %s found (current is %s) - do you want to update? [Y/n]: " % (TC.CYAN, TC.END, pjs_curr, PJS_VER))

            elif not force:
                choice = raw_input("\n  %s[!]%s phantomJS was not found - do you want to install it? [Y/n]: " % (TC.YELLOW, TC.END) )

            if not (force or (choice.lower() in ("y", "yes", '')) ):
                print("\n  %s[!]%s Exiting...\n\n" % (TC.YELLOW, TC.END) )
                sys.exit(0)

            else:
                pre = "phantomjs-%s" % PJS_VER
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

                try: shutil.rmtree("data/phantomjs")
                except: pass

                try:
                    u = urllib2.urlopen(url)
                    meta = u.info()
                    file_size = int(meta.getheaders("Content-Length")[0])
                    print "  %s[>]%s Updating phantomJS\n\t[%s] -" % (TC.GREEN, TC.END, url),
    
                    file_size_dl = 0
                    with open("data/" + fname, 'wb') as f:
                        while True:
                            buffer = u.read(8192)
                            if not buffer: break
    
                            file_size_dl += len(buffer)
                            f.write(buffer)
                            status = r"%7d [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
                            status = status + chr(8)*(len(status)+1)
                            print status,

                    if os.path.exists("data/phantomjs"):
                        if not os.access("data/phantomjs", os.W_OK):
                            import stat
                            os.chmod("data/phantomjs", stat.S_IWUSR)

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

                    print("\n")

                except urllib2.URLError, ex:
                    print("  %s[!]%s Unable to download file.\n\n\t %s\n" % (TC.RED, TC.END, ex))
                    exit(1)

        else:
            print("  %s[i]%s phantomJS %s found (current supported version)\n" % (TC.CYAN, TC.END, pjs_curr) )


    # DPE Database
    u = urllib2.urlopen(DPE_DL_PATH)
    meta = u.info()
    file_size = int(meta.getheaders("Content-Length")[0])

    try: cfile_size = os.path.getsize(DPE_FILE)
    except: cfile_size = 0

    if force or file_size != cfile_size:
        if not force:
            choice = raw_input("\n  %s[!]%s Update %s from [%s]? [Y/n]: " % (TC.YELLOW, TC.END, DPE_FILE, DPE_DL_PATH))

        if force or choice.lower() in ("y", "yes", ''):
            try: os.remove(DPE_FILE)
            except: pass

            print "  %s[>]%s Updating DPE.xml\n\t[%s] -" % (TC.GREEN, TC.END, DPE_DL_PATH),
        
            file_size_dl = 0
            with open(DPE_FILE, 'wb') as f:
                while True:
                    buffer = u.read(8192)
                    if not buffer: break
        
                    file_size_dl += len(buffer)
                    f.write(buffer)
                    status = r"%7d [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
                    status = status + chr(8)*(len(status)+1)
                    print status,

            print("\n")

    else:
        print("  %s[i]%s DPE Database at current version." % (TC.CYAN, TC.END) )


    # Ip2Country
    try:
        with open(IP_TO_COUNTRY) as f:
            for c, l in enumerate(f):
                if "# Software Version" in l:
                    ip2c_curr = l.split(" ")[5].replace('\n', '')
                    break

    except: ip2c_curr = 0

    if force or IP2C_VER > ip2c_curr:
        choice = 'y'
        if not force: 
            choice = raw_input("\n  %s[!]%s Update IpToCountry.csv (rev.%s > rev.%s)? [Y/n]: " % (TC.YELLOW, TC.END, ip2c_curr, IP2C_VER))

        if choice.lower() in ("y", "yes", ''):
            try: os.remove(IP_TO_COUNTRY)
            except: pass

            url = REPO_DL_PATH + IP_TO_COUNTRY.split("/")[1] + ".tar.gz"
            u = urllib2.urlopen(url)
            meta = u.info()
            file_size = int(meta.getheaders("Content-Length")[0])
            print "  %s[>]%s Updating IpToCountry.csv\n\t[%s] -" % (TC.GREEN, TC.END, url),
        
            file_size_dl = 0
            with open(IP_TO_COUNTRY + ".tar.gz", 'wb') as f:
                while True:
                    buffer = u.read(8192)
                    if not buffer: break
    
                    file_size_dl += len(buffer)
                    f.write(buffer)
                    status = r"%7d [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
                    status = status + chr(8)*(len(status)+1)
                    print status,

            tarfile.open(IP_TO_COUNTRY + ".tar.gz").extractall('./data')
            os.remove(IP_TO_COUNTRY + ".tar.gz")

            print("\n")

    else:
        print("\n  %s[i]%s %s - already at ver.%s\n" % (TC.CYAN, TC.END, IP_TO_COUNTRY, IP2C_VER))

    print("  %s[i]%s Update Complete\n\n" % (TC.BLUE, TC.END) )
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
        msg = re.sub("""\033\[(?:0|9[0-9])m""", '', str(msg))  #  clear out the terminal color formatting
        open(logfile, 'a').write("%s\n" % msg)
