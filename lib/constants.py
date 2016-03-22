VERSION = "0.5"

# Update information
REPO_DL_PATH = "https://bitbucket.org/al14s/rawr/downloads/"
IP_TO_COUNTRY = "data/IpToCountry.csv"
DPE_DL_PATH = "http://www.toolswatch.org/dpe/dpe_db.xml"
DPE_FILE = "data/dpe_db.xml"
VER_FILE = "ver.csv"
DEFPASS_VER = "2"
IP2C_VER = "5.9.1"
PJS_VER = "1.9.8"

# doc extensions for detection during crawl
DOC_TYPES = ("DS_Store", "pdf", "log", "dot", "doc", "docx", "xls", "xlsx", "txt", "ods", "odf", "ppt", "pptx",
             "rtf", "odg", "odp", "potx", "potm", "pot", "otp", "xlt", "stc", "stw", "dotm", "odb", "ott",
             "pxl", "wks", "wk1", "xlsb", "sylk", "xlc", "dif", "oth", "xml", "odt", "pptm", "xlm", "xltm",
             "xltx", "docm", "xlsm", "123", "dbf", "ppsx", "ps1", "pl", "bat", "vbs", "py", "rb", "sh",
             "jpeg", "jpg", "tiff", "wav", "riff")
OTHER_TYPES = ("cab", "swf", "jsp", "db", "gif", "png", "rar", "xz", "gz", "tar", "zip", "ico")

# Files used by the Google Dorks lookup for each host
DORKS_FILETYPES = ("DS_Store", "pdf", "log", "dot", "doc", "docx", "xls", "xlsx", "txt", "ods", "odf", "ppt", "pptx",
                   "vbs", "py", "ps1", "bat", "dbf", "xml", "rb", "sh")

# keep these out of our generated wordlists
ELEMENT_NAMES = ('!DOCTYPE', 'a', 'abbr', 'acronym', 'address', 'applet', 'area', 'article', 'aside', 'audio',
                 'b', 'base', 'basefont', 'bdi', 'bdo', 'big', 'blockquote', 'body', 'br', 'button', 'canvas',
                 'caption',
                 'center', 'cite', 'code', 'col', 'colgroup', 'datalist', 'dd', 'del', 'details', 'dfn', 'dialog',
                 'dir',
                 'div', 'dl', 'dt', 'em', 'embed', 'fieldset', 'figcaption', 'figure', 'font', 'footer', 'form',
                 'frame',
                 'frameset', 'h1', 'head', 'header', 'hr', 'html', 'i', 'iframe', 'img', 'input', 'ins', 'kbd',
                 'keygen',
                 'label', 'legend', 'li', 'link', 'main', 'map', 'mark', 'menu', 'menuitem', 'meta', 'meter', 'nav',
                 'noframes', 'noscript', 'object', 'ol', 'optgroup', 'option', 'output', 'p', 'param', 'pre',
                 'progress',
                 'q', 'rp', 'rt', 'ruby', 's', 'samp', 'script', 'section', 'select', 'small', 'source', 'span',
                 'strike',
                 'strong', 'style', 'sub', 'summary', 'sup', 'table', 'tbody', 'td', 'textarea', 'tfoot', 'th', 'thead',
                 'time', 'title', 'tr', 'track', 'tt', 'u', 'ul', 'var', 'video', 'wbr')

# PhantomJS - http://phantomjs.org/
PJS_REPO = "https://bitbucket.org/ariya/phantomjs/downloads/"
# Tell OSX not to let phantomjs steal focus or create a new icon in the dock for every instance.
OSX_PLIST = """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist SYSTEM "file://localhost/System/Library""" + \
            """/DTDs/PropertyList.dtd"><plist version="0.9"><dict><key>CFBundleExecutable</key><string>""" + \
            """phantomjs</string><key>CFBundleIdentifier</key><string>org.phantomjs</string><key>LSUIElement""" + \
            """</key><string>1</string></dict></plist>"""

# Regex for pulling URLs out of a string - http://daringfireball.net/2009/11/liberal_regex_for_matching_urls
URL_REGEX = """http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"""

# Detects nonroutable IPs
NRIP_REGEX = """((?:127.0.0.1|(?:10\.(?:25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])|192\.168|172\.(?:1""" + \
             """[6-9]|2[0-9]|3[0-1]))(?:\.(?:25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])){2}))"""

# Regex for checking NMap input
NMAP_INPUT_REGEX = '^((25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9])([-,](25[0-4]|2[0-4][0-9]|1[0-9]{2}|' + \
                   '[1-9][0-9]|[1-9]))*|\*)\.(((25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9]*[0-9])([-,](25[0-4]|' + \
                   '2[0-4][0-9]|1[0-9]{2}|[1-9]*[0-9]))*|\*)\.){2}((25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9]*' + \
                   '[0-9])([-,](25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9]*[0-9]))*|\*|([0]/(8|9|[1-2][0-9]|30|31|32)))$'

# For the sec headers grid
SECURITY_HEADERS = [('access-control-allow-origin',
                     [('*', '<td bgcolor="FF4D4D">Defined, <b>Allows All (*)</b></td>'),
                      ('', '<td bgcolor="80FF80">Defined, <<>></td>')],
                     '<td bgcolor="FF4D4D">Undefined</td>'),

                    ('content-security-policy',
                     [('', '<td bgcolor="80FF80"><<>></td>')],
                     '<td bgcolor="FF4D4D">Undefined</td>'),

                    ('server',
                     [('', '<td bgcolor="FF4D4D">Defined, <<>></td>')],
                     '<td bgcolor="80FF80">Undefined</td>'),

                    ('strict-transport-security',
                     [('', '<td bgcolor="80FF80"><<>></td>')],
                     '<td bgcolor="FF4D4D">Undefined</td>'),

                    ('x-content-type-options',
                     [('', '<td bgcolor="80FF80"><<>></td>')],
                     '<td bgcolor="FF4D4D">Undefined</td>'),

                    ('x-frame-options',
                     [('', '<td bgcolor="80FF80"><<>></td>')],
                     '<td bgcolor="FF4D4D">Undefined</td>'),

                    ('x-permitted-cross-domain-policies',
                     [('x-permitted-cross-domain-policies: (.*)', '<td bgcolor="80FF80"><<>></td>')],
                     '<td bgcolor="FF4D4D">Undefined</td>'),

                    ('x-powered-by',
                     [('', '<td bgcolor="FF4D4D">Defined, <<>></td>')],
                     '<td bgcolor="80FF80">Undefined</td>'),

                    ('x-xss-protection',
                     [('0', '<td bgcolor="FF4D4D"><b>Protection Disabled,</b> x-xss-protection: 0</td>'),
                      ('', '<td bgcolor="80FF80">Defined, <<>></td>')],
                     '<td bgcolor="FF4D4D">Undefined</td>')

                    ]


# Diagram prefs
LAYOUT_TYPE = 'dot'
ROOT_NODE_SHAPE = 'circle'  # http://www.graphviz.org/doc/info/shapes.html
ROOT_NODE_COLOR = 'blue'  # http://www.graphviz.org/doc/info/colors.html
EXTERNAL_NODE_SHAPE = 'box'  # http://www.graphviz.org/doc/info/shapes.html
EXTERNAL_NODE_COLOR = 'orangered'  # http://www.graphviz.org/doc/info/colors.html


# Terminal color defs
class TC:
    def __init__(self):
        pass

    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    END = '\033[0m'
