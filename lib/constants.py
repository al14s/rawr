VERSION = "0.1.72"

# Update information
REPO_DL_PATH = "https://bitbucket.org/al14s/rawr/downloads/"
IP_TO_COUNTRY = "data/IpToCountry.csv"
DEFPASS_FILE = "data/defpass.csv"
VER_FILE = "ver.csv"

# doc extensions for detection during crawl
DOC_TYPES = ("DS_Store", "pdf", "log", "dot", "doc", "docx", "xls", "xlsx", "txt", "ods", "odf", "ppt", "pptx", "tar",
             "rtf", "odg", "odp", "potx", "potm", "pot", "otp", "xlt", "stc", "stw", "dotm", "odb", "ott", "zip",
             "pxl", "wks", "wk1", "xlsb", "sylk", "xlc", "dif", "oth", "xml", "odt", "pptm", "xlm", "xltm", "gz",
             "cab", "xltx", "docm", "xlsm", "123", "dbf", "ppsx", "ps1", "pl", "bat", "vbs", "py", "rb", "sh")

# PhantomJS - http://phantomjs.org/
PJS_REPO = "http://phantomjs.googlecode.com/files/"
#Tell OSX not to let phantomjs steal focus or create a new icon in the dock for every instance.
OSX_PLIST = """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist SYSTEM "file://localhost/System/Library""" +\
            """/DTDs/PropertyList.dtd"><plist version="0.9"><dict><key>CFBundleExecutable</key><string>""" +\
            """phantomjs</string><key>CFBundleIdentifier</key><string>org.phantomjs</string><key>LSUIElement""" +\
            """</key><string>1</string></dict></plist>"""

# Regex for pulling URLs out of a string - http://daringfireball.net/2009/11/liberal_regex_for_matching_urls
URL_REGEX = """http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"""

# Regex for checking NMap input
NMAP_INPUT_REGEX = '^((25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9])([-,](25[0-4]|2[0-4][0-9]|1[0-9]{2}|' +\
                   '[1-9][0-9]|[1-9]))*|\*)\.(((25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9]*[0-9])([-,](25[0-4]|' +\
                   '2[0-4][0-9]|1[0-9]{2}|[1-9]*[0-9]))*|\*)\.){2}((25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9]*' +\
                   '[0-9])([-,](25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9]*[0-9]))*|\*|([0]/(8|9|[1-2][0-9]|30|31|32)))$'

# Diagram prefs
ROOT_NODE_SHAPE = 'circle'  # http://www.graphviz.org/doc/info/shapes.html
ROOT_NODE_COLOR = 'blue'  # http://www.graphviz.org/doc/info/colors.html
EXTERNAL_NODE_SHAPE = 'box'  # http://www.graphviz.org/doc/info/shapes.html
EXTERNAL_NODE_COLOR = 'orangered'  # http://www.graphviz.org/doc/info/colors.html