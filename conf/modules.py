# MODTYPES - The different functions your module can perform
WHOLEDOC_CONTENT = 0    # Places all matches into the specified field.
WHOLEDOC_TRUEFALSE = 1  # Places 'True' or 'False' based on the WHOLEDOC.
WHOLEDOC_COUNT = 2      # Places the number of results in the specified field.
PARSER_CONTENT = 3      # Places all matches into the specified field.
PARSER_TRUEFALSE = 4    # Places 'True' or 'False' based on tag and attr specifications.
PARSER_COUNT = 5        # Places the number of results in the specified field.

# Format
#	WHOLEDOC: ( <field name>, <regex>, <type>, <usable for nonHTML> )
#	PARSER:   ( <field name>, [<tag>, ("<attrib>"|"text"), <regex>], <type>, <usable for nonHTML>  )

modules = [
    (
        "analytics_id",                                  # store the results in the 'analytics_ID' column
        """["']UA-[0-9]{8}-[0-9]{1}["']""",              # look for google analytics IDs
        WHOLEDOC_CONTENT,                                # Search the whole response content
        False),  
    (
        "index_pages",
        """[Ii]ndex [Oo]f""",
        WHOLEDOC_TRUEFALSE,
        False),
    (
        "locations",
        """[^http:](?:[a-zA-Z]:[\\\\]{1,}|file:[\\\\]{1,}|[\\\\]{1,})((?:[\\\\]{1,}[a-z.A-Z0-9]{1,30}){2,}[/|\\\\]?)""",
        WHOLEDOC_CONTENT,
        True),
    (
        "email_addresses",                               # store the results in the 'email_addresses' column
        """([a-zA-Z0-9._+-]{2,}@[a-zA-Z0-9.-]{1,}\.(?:[A-Z]{2,4}|[a-z]{2,4}))""",    # look for email addresses
        WHOLEDOC_CONTENT,                                # Search the whole response content
        True),
    #(
    #    "keywords",
    #    """((?:username|un|user|password|passwd|pwd|pw)[\:\s]+[^\n\r]{,10})""",  # One of the keywords + 10 chars
    #    WHOLEDOC_CONTENT,
    #    True),
    (
        "urls",
        """(http[s]?://[0-9a-zA-Z.@:&+-]+(?:[/][0-9a-zA-Z-&\?]+)+(?:[/]|[.][0-9a-z][0-9a-z-]{0,2}|[.][0-9A-Z][0-9A-Z-]{0,2}]))""",
        WHOLEDOC_CONTENT,
        True),
    (
        "files",  # needs testing
        """(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)""",
        WHOLEDOC_CONTENT,
        True),
    (
        "us_phone_numbers",
        """((?:(?:[\(\[][2-9]{1}[0-9]{2}[\)\]]|[2-9]{1}[0-9]{2})[\-\s]{1}){0,1}[2-9]{3}[\-]{1}[0-9]{4})[^\-]""",
        WHOLEDOC_CONTENT,
        True),                                          # Should be used during document/image document parsing
    (
        "unc_paths",                                   # store the results in the 'share_paths' column
        """[^http:](?:[a-zA-Z]:[\\\\]{1,}|file:[\\\\]{1,}|[\\\\]{1,})((?:[\\\\]{1,}[a-z.A-Z0-9]{1,30}){2,}[/|\\\\]?)""",
        WHOLEDOC_CONTENT,                                # Search the whole response content
        True),                                          # Should be used during document/image document parsing
    (
        "sql_statements",
        """(ALTER|CREATE|DELETE|DROP|EXEC(?:UTE)?|INSERT(?:INTO)?|MERGE|SELECT|UPDATE|UNION(?:ALL)?[^;\"\'])""",
        WHOLEDOC_CONTENT,
        True),
    (
        "internal_ips",
        """((?:127.0.0.1|(?:10\.(?:25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9])|192\.168|172\.""" +
		"""(?:1[6-9]|2[0-9]|3[0-1]))(?:\.(?:25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[1-9])){2}))""",
        WHOLEDOC_CONTENT,
        True),
    (
        "users",
		"""(?:[a-zA-Z]:[\\\\]{1,}[U|u]sers|[D|d]ocuments and [S|s]ettings)[\\\\]{1,}(.*?)[\\\\]{1,}""",
        WHOLEDOC_CONTENT,
        True),
    (
        "html5",
        """<!DOCTYPE html>""",
        WHOLEDOC_TRUEFALSE,
        False),
    (
        "jquery",
        ("script", ("src", "href"), """jquery"""),       # SCRIPT tags in SRC & HREF attr - look for the regxp "jquery"
        PARSER_CONTENT,
        False),
    (
        "comments",
        """<!--(.*?)-->""",
        WHOLEDOC_CONTENT,
        False),
    (
        "docwrites",
        """document.write'""",
        WHOLEDOC_CONTENT,
        False),
    (
        "flash_objects",
        """new[\s]+FlashObject[\s]*\([\s]*['"]?[^'^"]+""",
        WHOLEDOC_COUNT,
        False),
    (
        "flash_objects",
        """new[\s]+SWFObject[\s]*\([\s]*['"]?[^'^"]+""",
        WHOLEDOC_COUNT,
        False),
    (
        "flash_objects",
        """\.embedSWF[\s]*\([\s]*["']?[^'^"]+""",
        WHOLEDOC_COUNT,
        False)
]
