PARSER 					= 0
WHOLE_DOC				= 1

MODTYPE_MATCH 			= 0     # Places all matches into the specified field.
MODTYPE_TRUEFALSE		= 1     # Places 'True' or 'False' based on the regex.
MODTYPE_COUNT 			= 2     # Places the number of results in the specified field.

#	( <field name>, <regex for search>, <type> ),
modules = {
	( "analytics_ID",   """["']UA-[0-9]{8}-[0-9]{1}["']""",                                     MODTYPE_MATCH,		WHOLE_DOC   ),
	#( "ga_docwrites",  """old google analytics doc.writes'""",                                  MODTYPE_MATCH,		WHOLE_DOC    ),
	#( "documents",  """*.pdf...""",                                                             MODTYPE_MATCH,		WHOLE_DOC    ),
	( "passwordfields", """password""", 								                        MODTYPE_MATCH,		PARSER		),
	#( "file_calls",  """show all file includes""",                                              MODTYPE_MATCH,		PARSER  	 ),
	#( "Flash_Objects",  """/<object[^>]+application\/x-shockwave-flash[^>]+>/i""",              MODTYPE_MATCH,		PARSER  	 ),
	#( "Flash_Objects",  """/<embed[^>]+src[\s]*=[\s]*["']?[^\s^'^"^>]+/i""",                    MODTYPE_MATCH,		PARSER  	 ),
	#( "Flash_Objects",  """/new[\s]+FlashObject[\s]*\([\s]*['"]?[^'^"]+/""",                    MODTYPE_MATCH,		PARSER  	 ),
	#( "Flash_Objects",  """/new[\s]+SWFObject[\s]*\([\s]*['"]?[^'^"]+/""",                      MODTYPE_MATCH, 	PARSER  	 ),
	#( "Flash_Objects",  """/\.embedSWF[\s]*\([\s]*["']?[^'^"]+/""",                             MODTYPE_MATCH,		WHOLE_DOC    ),
	#( "Java_Applets",   """/<applet[^>]+code[\s]*=[\s]*["|']?([^\s^>^"^']+)[^>]*>/i""",         MODTYPE_MATCH,		PARSER  	 ),
	#( "JQuery",         """>/jquery.js\?ver=([0-9\.]+)""",                                      MODTYPE_MATCH,		PARSER  	 ),
	#( "IFrames",        """>/<[\s]*[i]?frame[^>]+src[\s]*=[\s]*["|']?([^>^"^'^\s]+)/i""",       MODTYPE_MATCH,		PARSER   	 ),
	#( "JS_common",      """common.js""",                                                        MODTYPE_MATCH,		WHOLE_DOC    ),
	#( "JS_Params",      """url params in use / being checked""",                                MODTYPE_MATCH,		WHOLE_DOC    ),
	#( "file_includes",  """js,css,etc...""",                                                    MODTYPE_MATCH,		WHOLE_DOC    ),
	( "emailaddresses", """[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}""",                           MODTYPE_MATCH,		WHOLE_DOC   ),
	( "emailaddresses", """<[^>]+href=[^>]*mailto:([^\'\"\?>]+)[^>]*>""",                       MODTYPE_MATCH,		PARSER		),
	#( "ftp_links",      """<!DOCTYPE html>""",                                                  MODTYPE_MATCH,		WHOLE_DOC	 ),
	( "HTML5",          """<!DOCTYPE html>""",                                                  MODTYPE_TRUEFALSE,	WHOLE_DOC	)
}
