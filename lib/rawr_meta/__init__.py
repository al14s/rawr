from __future__ import print_function
import re, binascii, os, zipfile, shutil, sys, string
from PIL import Image
from glob import glob
from lxml import etree
from stat import *
import datetime
from zlib import decompress as zlib_decomp
from time import mktime, strptime

import os
import OleFileIO_PL
from docx import *

from rawr_meta import Meta_Parser
