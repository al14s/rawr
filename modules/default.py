
MODTYPE_CONTENT =   0     # Places all matches into the specified field.
MODTYPE_TRUEFALSE = 1     # Places 'True' or 'False' based on the regex.
MODTYPE_COUNT =     2     # Places the number of results in the specified field.

#	( <field name>, <regex for search>, <type> ),
modules = {
	( "analytics_ID",   """["']UA-[0-9]{8}-[0-9]{1}["']""",                                     MODTYPE_CONTENT   ),
	#( "ga_docwrites",  """old google analytics doc.writes'""",                                  MODTYPE_CONTENT   ),
	#( "documents",  """*.pdf...""",                                                             MODTYPE_CONTENT   ),
	( "passwordfields", """<input [^>]*?type=["']password["'][^>]*>""",                         MODTYPE_CONTENT   ),
	#( "Flash_Objects",  """/new[\s]+FlashObject[\s]*\([\s]*['"]?[^'^"]+/""",                    MODTYPE_CONTENT   ),
	#( "Flash_Objects",  """/new[\s]+SWFObject[\s]*\([\s]*['"]?[^'^"]+/""",                      MODTYPE_CONTENT   ),
	#( "Flash_Objects",  """/\.embedSWF[\s]*\([\s]*["']?[^'^"]+/""",                             MODTYPE_CONTENT   ),
	#( "JQuery",         """>/jquery.js\?ver=([0-9\.]+)""",                                      MODTYPE_CONTENT   ),
	#( "JS_common",      """common.js""",                                                        MODTYPE_CONTENT   ),
	#( "JS_Params",      """url params in use / being checked""",                                MODTYPE_CONTENT   ),
	#( "file_includes",  """js,css,etc...""",                                                    MODTYPE_CONTENT   ),
	( "emailaddresses", """[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}""",                           MODTYPE_CONTENT   ),
	( "emailaddresses", """<[^>]+href=[^>]*mailto:([^\'\"\?>]+)[^>]*>""",                       MODTYPE_CONTENT   ),
	( "HTML5",          """<!DOCTYPE html>""",                                                  MODTYPE_TRUEFALSE ),
	#( "ftp_links",      """<!DOCTYPE html>""",                                                  MODTYPE_CONTENT   ),
}
