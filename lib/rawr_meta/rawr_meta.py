#!/usr/bin/python

from __future__ import print_function
import re
import binascii
import zipfile
import shutil
import sys
import string
import os
import time
import datetime
from glob import glob
from lxml import etree
from stat import *
from zlib import decompress as zlib_decomp
from time import mktime, strptime

# Local Imports
import OleFileIO_PL
import docx


class Meta_Parser(object):
    def __init__(self):

        try:
            from conf.modules import modules
            self.CONTENT_REGEXES = [m for m in modules if m[-1]]

        except:
            print("using builtin self.CONTENT_REGEXES")

            self.CONTENT_REGEXES = [
                ("internal_ips",
                 "((?:127.0.0.1|(?:10\.(?:25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9])|192\.168|172\." +
                 "(?:1[6-9]|2[0-9]|3[0-1]))(?:\.(?:25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9])){2}))"),
                ("email_addresses",
                 "([a-zA-Z0-9._+-]{1,}@[a-zA-Z0-9.-]{1,}\.[a-z]{2,5}|[a-zA-Z0-9._+-]{1,}@[a-zA-Z0-9.-]{1,}" +
                 "\.[a-z]{2,5})"),
                ("phone_numbers",
                 "((?:(?:[\(\[][2-9]{1}[0-9]{2}[\)\]]|[2-9]{1}[0-9]{2})[\-\s]{1}){0,1}[2-9]{3}[\-]{1}[0-9]{4})[^\-]"),
                ("users", "(?:[a-zA-Z]:[\\\\]{1,}[U|u]sers|[D|d]ocuments and [S|s]ettings)[\\\\]{1,}(.*?)[\\\\]{1,}"),
                ("urls",
                 "(http[s]?://[0-9a-zA-Z.@:&+-]+(?:[/][0-9a-zA-Z-&\?]+)+(?:[/]|[.][0-9a-z][0-9a-z-]{0,2}|[.]" +
                 "[0-9A-Z][0-9A-Z-]{0,2}]))"),
                ("locations",
                 "[^http](?:[a-zA-Z]:[\\\\]{2,}|file:[\\\\]{1,}|[\\\\]{1,})((?:[\\\\]{1,}[a-z.A-Z0-9]{1,30})" +
                 "{2,}[/|\\\\]?)")
                # ,
                # ("sql_statements", """(ALTER|CREATE|DELETE|DROP|EXEC(?:UTE)?|INSERT(?:INTO)?|MERGE|SELECT|" +
                #  "UPDATE|UNION(?:ALL)?[^;\"\'])"""),
                # ("keywords", """((?:username|un|user|password|passwd|pwd|pw)[\:\s]+[^\n\r]{,10})""")
            ]

        self.PDF_IGNORED = ['FontFamily', 'Ordering', 'Registry']

        self.DOCUMENT_SEC = {0: 'None',
                             1: 'Password protected',
                             2: 'Read-only recommended',
                             4: 'Read-only enforced',
                             8: 'Locked for annotations'}

        self.CODEPAGE_VALS = {1250: 'Central/Eastern European Latin',
                              1251: 'Cyrillic',
                              1252: 'Latin-1',
                              1253: 'Greek',
                              1254: 'Turkish',
                              1255: 'Hebrew',
                              1256: 'Arabic',
                              1257: 'Baltic',
                              1258: 'Vietnamese',
                              874: 'Thai',
                              932: 'Japanese Shift-JIS',
                              936: 'Simplified Chinese GBK',
                              949: 'Korean',
                              950: 'Traditional Chinese Big5'
                              }

    def pdf(self, fn):
        props = {}
        fdat = open(fn, 'rb').read()

        for data in fdat.split('Filter'):
            try:
                t = data.split('>>')[0].split('/')[1]
                content = data.split('\r\nendstream')[0].split('stream\r\n')[1]
                # streams that are pics/files?
                if t == 'FlateDecode':  # just flatedecode for now...
                    fdat = fdat.replace(content, zlib_decomp(content))

            except:
                pass

        props = self.addto(props, self.mod_checks(fdat))

        try:
            for item in re.findall("<<(.*?/CreationDate.*?)>>", fdat)[0].split('/')[1:]:
                prop = item.split('(')[0]
                try:
                    #  Producer(Acrobat Distiller 6.0.1 \(Windows\))
                    val = filter(lambda x: x in string.printable, item).replace('\\(', '><').replace('\\)', '<>')
                    #  Producer(Acrobat Distiller 6.0.1 ><Windows)
                    val = val.split('(')[1].rstrip(')').replace('><', '(').replace('<>', ')')
                    #  Acrobat Distiller 6.0.1 (Windows)

                except:
                    continue

                if not (prop in self.PDF_IGNORED or len(prop) < 3):
                    if prop in ('Creator', 'Producer'):
                        props = self.addto(props, 'Software', val)

                    elif prop in ('ModDate', 'CreationDate', 'SourceModified', 'LastModified'):
                        dt = datetime.datetime.strptime(val[2:15], "%Y%m%d%H%M%S")
                        props = self.addto(props, 'dates', "<small><b>" + prop + "</b>: " + dt.strftime(
                            "%m-%d-%Y %H:%M:%S") + '</small>')

                    elif prop == 'URI':
                        props = self.addto(props, 'urls', val)

                    elif prop == 'Author':
                        props = self.addto(props, 'users', val)

                    else:
                        props = self.addto(props, prop, val)

        except:
            pass

        if 'rdf:RDF' in fdat:
            dat = re.sub('[\\r\\n\\t]', '', fdat.split('<rdf:RDF')[1].split('</rdf:RDF')[0])

            arr = [('Software', "x[am]p:CreatorTool>(.*)</x[am]p:CreatorTool>"),
                   ('ModifyDate', "x[am]p:ModifyDate>(.*)</x[am]p:ModifyDate>"),
                   ('CreateDate', "x[am]p:CreateDate>(.*)</x[am]p:CreateDate>"),
                   ('MetadataDate', "x[am]p:MetadataDate>(.*)</x[am]p:MetadataDate>"),
                   # ('Filetype',     "<dc:format>(.*)</dc:format>"),   ignoring this for now
                   ('Title', '<dc:title><rdf:Alt><rdf:li[\\s]?xml:lang=".*">(.*)</rdf:li></rdf:Alt></dc:title>'),
                   ('users', "<dc:creator><rdf:Seq><rdf:li>(.*)</rdf:li></rdf:Seq></dc:creator>"),
                   ('Software', "<pdf:Producer>(.*)</pdf:Producer>")]

            for a in arr:
                try:
                    if a[0].endswith('Date'):
                        dt = datetime.datetime.strptime(a[1][:20], "%Y-%m-%dT%H%M%S")
                        props = self.addto(props, 'dates', "<small><b>" + a[0] + "</b>: " + dt.strftime(
                            "%m-%d-%Y %H:%M:%S") + '</small>')

                    props = self.addto(props, a[0], re.findall(a[1], filter(lambda x: x in string.printable, dat))[0])

                except:
                    pass

        return props

    def addto(self, i1, i2, val=None):  # update a dict or combine two dicts, appending to lists instead of overwriting
        if (type(i1), type(i2), val) == (dict, dict, None):
            for k in i2:
                i1 = self.addto(i1, k, i2[k])

        else:
            if type(val) == dict:
                for k in val:
                    if i2 not in i1:
                        i1[i2] = {}

                    i1[i2] = self.addto(i1[i2], k, val[k])

            elif type(val) == list:
                for k in val:
                    i1 = self.addto(i1, i2, k)

            else:
                try:
                    if val not in i1[i2]:
                        i1[i2].append(val)
                except:
                    try:
                        if not val == i1[i2]:
                            i1[i2] = [i1[i2], val]
                    except:
                        i1[i2] = val

        return i1

    def mod_checks(self, f):
        try:
            with open(f) as of:
                z = re.sub('[\r\n]', " ", filter(lambda x: x in string.printable, of.read()))

        except:
            z = self.safe_string(f)

        try:
            wl = list(set(re.findall('^[a-zA-Z0-9]{3,}$', z)))
            out = {'words': wl}

        except:
            out = {}

        for m in self.CONTENT_REGEXES:
            if m[-1]:
                dat = re.findall(m[1], z)
                if len(dat) > 0:
                    for i in list(dat):
                        if not any([t for t in ('docs.oasis-open.org', 'ns.adobe.com',
                                                'www.apple.com/DTDs/PropertyList-1.0.dtd', 'schemas.',
                                                'purl.org', 'w3.org', 'openoffice.org') if t in i]):

                            i = self.safe_string(i).replace('\\\\', '\\').replace('\\\\\\\\',
                                                                                  '\\\\').replace('_x000d_', '')
                            out = self.addto(out, m[0], i)

                            if not m[0] == 'users':
                                z = z.replace(i, '')

        return out

    def msoffice_meta(self, fn):
        ret = {}
        try:
            dat = open(fn, 'rb').read()

            if fn.split('/')[-1] == 'document.xml':
                dat = re.sub('<.*?>', '   ', dat)
                ret = self.addto(ret, self.mod_checks(fn))

            elif fn == './tmp/docProps/core.xml':
                dat = dat.split('<cp:coreProperties')[1].split('<')
                for i in dat:
                    t, v = i.split('>')
                    if v:
                        t = t.split(':')[1].split()[0]

                        if t in ('created', 'modified', 'lastPrinted'):
                            dt = datetime.datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
                            ret = self.addto(ret, 'dates', "<small><b>" + t.title() + "</b>: " + dt.strftime(
                                "%m-%d-%Y %H:%M:%S") + "</small>")

                        elif t in ('creator', 'lastModifiedBy'):
                            ret = self.addto(ret, 'users', v)

                        else:
                            ret[t] = v.replace('_x000d_', '')

            else:
                t = re.findall("lpstr>(.*?)</vt:lpstr>", dat)
                if len(t) > 0:
                    ret['worksheet names'] = ', '.join(t)

                t = re.findall("<Application>(.*?)</Application>.*?<AppVersion>(.*?)</AppVersion>", dat)
                if len(t) > 0:
                    ret['Software'] = ' '.join(t[0])

                ret['Statistics'] = []
                # for t, v in re.findall("<(.*?)(?: [.*])?>(.*?)</", dat):
                for t, v in re.findall("<(.*?)>(.*?)</", dat):
                    if v and not any([i for i in ('openoffice.org', ':', '/', 'AppVersion', 'HeadingPairs',
                                                  'HyperlinksChanged', 'LinksUpToDate', 'ScaleCrop') if i in t]):
                        if t in ('Slides', 'Words', 'Paragraphs', 'HiddenSlides', 'Notes', 'MMClips',
                                 'Words', 'CharactersWithSpaces', 'Pages', 'Characters', 'Lines'):
                            ret['Statistics'].append(t + ': ' + v + '  ')

                        elif t == 'SharedDoc':
                            if not v == 'false':
                                ret[t] = v

                        elif t in ('SourceModified', 'CreationDate', 'ModDate'):
                            dt = datetime.datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
                            ret = self.addto(ret, 'dates', "<small><b>" + t.title() + "</b>: " + dt.strftime(
                                "%m-%d-%Y %H:%M:%S") + "</small>")

                        elif t == 'HyperlinkBase':
                            ret = self.addto(ret, 'urls', v)

                        elif t == 'DocSecurity':
                            if not int(v) == 0: ret[t] = SEC_VALS[int(v)]

                        elif t not in ('Application', 'TotalTime'):
                            ret[t] = v

                if not ret['Statistics']:
                    del ret['Statistics']

            return ret

        except:
            return {}

    def ooo_meta(self, fn):
        ret = {}
        dat = open(fn, 'rb').read()
        t = re.findall("generator>(.*?)<", dat)
        if len(t) > 0:
            ret['Software'] = t[0]

        t = re.findall("initial-creator>(.*?)<", dat)
        if len(t) > 0:
            ret = self.addto(ret, 'users', t[0])

        t = re.findall("creation-date>(.*?)<", dat)
        if len(t) > 0:
            dt = datetime.datetime.strptime(t[0], "%Y-%m-%dT%H:%M:%S")
            ret = self.addto(ret, 'dates', "<small><b>Created</b>: " + dt.strftime("%m-%d-%Y %H:%M:%S") + "</small>")

        t = re.findall("dc:creator>(.*?)<", dat)
        if len(t) > 0:
            ret = self.addto(ret, 'users', t[0])

        t = re.findall("dc:date>(.*?)<", dat)
        if len(t) > 0:
            dt = datetime.datetime.strptime(t[0], "%Y-%m-%dT%H:%M:%S")
            ret = self.addto(ret, 'dates', "<small><b>Date</b>: " + dt.strftime("%m-%d-%Y %H:%M:%S") + "</small>")

        # t = re.findall("editing-cycles>([0-9]+)<", dat)
        # if len(t) > 0:
        #    ret['editing-cycles'] = t[0]

        # t = re.findall("editing-duration>([A-Z0-9]+)<", dat)
        # if len(t) > 0:
        #    ret['editing-duration'] = t[0]

        t = re.findall("template.*xlink:title=\"(.*?)\"", dat)
        if len(t) > 0:
            ret['template'] = t[0]

        try:
            for tag, val in re.findall("user-defined.*meta:name=\"(.*?)\".+?>(.*?)<", dat):
                ret[tag] = val

        except:
            pass

        ret['Statistics'] = []
        try:
            for tag, val in re.findall("meta:([a-z\-]*?)=[\"](.*?)[\"] ",
                                       dat.split('document-statistic')[1].split('/>')[0]):
                if int(val) > 0:
                    ret['Statistics'].append(tag.replace('-count', 's') + ': ' + val + '  ')

        except:
            pass

        if not ret['Statistics']:
            del ret['Statistics']

        return ret

    def decompress(self, fn):
        ret = {}
        doc = zipfile.ZipFile(fn)

        try:
            os.mkdirs('./tmp')
        except:
            pass

        doc.extractall('./tmp/')
        for item in doc.infolist():
            x = self.file_parse('./tmp/' + item.orig_filename)
            if len(x.keys()) > 1:
                del x['filename']
                ret = self.addto(ret, x)

            if item.orig_filename == 'meta.xml':
                ret = self.addto(ret, self.ooo_meta('./tmp/' + item.orig_filename))

            elif item.orig_filename in ('docProps/app.xml',
                                        'docProps/core.xml') or item.orig_filename.split('/')[-1] \
                    in ('sharedStrings.xml', 'document.xml'):
                ret = self.addto(ret, self.msoffice_meta('./tmp/' + item.orig_filename))

        return ret

    def get_exif(self, f):
        ret = {'exif': {}}
        try:
            i = Image.open(f)
            try:
                items = i._getexif().items()
            except:
                items = i.tag.items()

            for i, v in items:
                if re.search('[a-zA-Z]+', str(v)):
                    ret['exif'] = self.addto(ret['exif'], i, v)

            if not ret['exif'] == {}:
                return ret

            else:
                return {}

        except:
            return {}

    def file_props(self, f):
        try:
            st = os.stat(f)
            import pwd
            userinfo = pwd.getpwuid(st[ST_UID])
            return {'creator': userinfo[0]}

        except:
            return {}

    def safe_string(self, s):
        try:
            return str(s)

        except UnicodeEncodeError:
            return unicode(s).encode('unicode_escape')

    def is_ole(self, f):
        meta = OleFileIO_PL.OleFileIO(f).get_metadata()
        ret = {}

        for prop in (meta.SUMMARY_ATTRIBS + meta.DOCSUM_ATTRIBS):
            value = getattr(meta, prop)
            if value:
                if prop == 'creating_application':
                    ret = self.addto(ret, 'Software', value)

                elif prop == 'security':
                    ret = self.addto(ret, 'security', SEC_VALS[value])

                elif prop in ('create_time', 'last_printed', 'last_saved_time'):
                    prop = prop.replace('num_', '').replace('_', ' ').replace(' time', '').title()
                    try:
                        prop += '</b>: ' + value.strftime("%m-%d-%Y %H:%M:%S")
                    except:
                        prop += '</b>: Never'

                    ret = self.addto(ret, 'dates', "<small><b>" + prop + "</small>")

                elif prop in ('author', 'last_saved_by'):
                    ret = self.addto(ret, 'users', value)

                elif prop in ('codepage', 'codepage_doc'):
                    try:
                        x = self.CODEPAGE_VALS[value]
                    except:
                        x = 'Unknown: ' + str(value)
                    ret = self.addto(ret, 'Encoding', x)

                elif prop in ('paragraphs', 'num_words', 'num_pages', 'num_chars', 'lines',
                              'chars_with_spaces', 'slides', 'notes'):
                    ret = self.addto(ret, 'Statistics',
                                     "%s: %s  " % (prop.replace('num_', '').replace('_', ' '), value))

                elif prop not in ('content_status', 'thumbnail', 'version', 'bytes', 'total_edit_time'):  # don't care
                    ret = self.addto(ret, prop, str(value))

        return ret

    def parse(self, f):
        doc = {'filename': f}
        fn, ext = os.path.splitext(f)

        # file_props(f)
        if os.path.isfile(f):
            if OleFileIO_PL.isOleFile(f):
                doc = self.addto(doc, self.is_ole(f))

            doc = self.addto(doc, self.get_exif(f))

            if ext == '.pdf':
                doc = self.addto(doc, self.pdf(f))

            else:
                try:
                    doc = self.addto(doc, self.decompress(f))

                except zipfile.BadZipfile:
                    doc = self.addto(doc, self.mod_checks(f))  # punt

        return doc

    def add_to_report(self, f, report_file, ret, loc):
        if len(ret.keys()) > 1:
            if not os.path.isfile(report_file):
                with open(report_file, 'w') as of:
                    of.write("""<html><head><title>Metadata Report</title><style>body {font-family:""" +
                             """ Arial, font-size:14px; Helvetica, sans-serif;} h4 {color:#6699CC;""" +
                             """ padding:7; margin:0;} table {border:1; padding:0;} td{padding:5;}""" +
                             """</style></head><body>""")

            with open(report_file, 'a') as of:
                del ret['filename']
                of.write('<h4>%s</h4><table cellpadding=0 cellspacing=0>' % loc)
                of.write('<tr><th width=20px /><th width=180px /><th width=10px /><th /></tr>')
                of.write('<tr valign="top"><td></td><td colspan=3><h5>%s</h5></td></tr>' % f)

                for key in ret.keys():
                    if type(ret[key]) == dict:
                        if len(ret[key].keys()) > 0:
                            y = []
                            for k in ret[key].keys():
                                if type(ret[key][k]) == list:
                                    if len(ret[key][k]) > 1 or str(ret[key][k][0]).strip():
                                        for i in ret[key][k]:
                                            y.append(str(i))

                                else:
                                    y.append(ret[key][k])

                        x = '<br />'.join(y)

                    elif type(ret[key]) == list:
                        if len(ret[key]) > 1 or str(ret[key][0]).strip():
                            x = []
                            for k in ret[key]:
                                if type(k) == dict:
                                    for i in k:
                                        x.append(str(i) + ' &nbsp; &nbsp; ' + str(', '.join(k[i])))

                                else:
                                    x.append(str(k))

                            x = '<br/>'.join(x)

                        else:
                            continue

                    else:
                        x = ret[key]

                    of.write('<tr valign="top"><td></td><td><b>%s</b></td><td></td><td>%s</td></tr>\n' %
                             (key.replace('_', ' ').title(), x))

                of.write('</table><br /><br />')


if __name__ == "__main__":
    start = time.time()
    parser = Meta_Parser()
    scope = glob(sys.argv[-1])

    report_file = 'meta_report_%s.html' % datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    for f in scope:
        if os.path.isfile(f) and not f == sys.argv[0]:
            ret = parser.parse(f)
            parser.add_to_report(f, report_file, ret, report_file)

    with open(report_file, 'a') as of:
        of.write('</body></html>')

    try:
        os.system('rm -rf ./tmp')
    except:
        pass

    elapsed = time.time() - start
    print("Time taken: ", elapsed, "seconds.")
