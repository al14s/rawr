
VERSION =       "0.1.5"

# Update information
REPO_DL_PATH =  "https://bitbucket.org/al14s/rawr/downloads/"
IP_TO_COUNTRY = "data/IpToCountry.csv"
DEFPASS_FILE =  "data/defpass.csv"
VER_FILE =      "ver.csv"

# PhantomJS - http://phantomjs.org/
PJS_REPO =      "http://phantomjs.googlecode.com/files/"
#Tell OSX not to let phantomjs steal focus or create a new icon in the dock for every instance.
OSX_PLIST =     """<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist SYSTEM "file://localhost/System/Library/DTDs/PropertyList.dtd"><plist version="0.9"><dict><key>CFBundleExecutable</key><string>phantomjs</string><key>CFBundleIdentifier</key><string>org.phantomjs</string><key>LSUIElement</key><string>1</string></dict></plist>"""

# Regex for pulling URLs out of a string - http://daringfireball.net/2009/11/liberal_regex_for_matching_urls
URL_REGEX =     """http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"""

