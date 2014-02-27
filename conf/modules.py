# MODTYPES - The different functions your module can perform
WHOLEDOC_CONTENT = 0    # Places all matches into the specified field.
WHOLEDOC_TRUEFALSE = 1  # Places 'True' or 'False' based on the WHOLEDOC.
WHOLEDOC_COUNT = 2      # Places the number of results in the specified field.
PARSER_CONTENT = 3      # Places all matches into the specified field.
PARSER_TRUEFALSE = 4    # Places 'True' or 'False' based on tag and attr specifications.
PARSER_COUNT = 5        # Places the number of results in the specified field.

# Format
#	WHOLEDOC: ( <field name>, <regex>, <type> )
#	PARSER:   ( <field name>, [<tag>, ("<attrib>"|"text"), <regex>], <type> )

modules = [
    (
        "analytics_ID",
        """["']UA-[0-9]{8}-[0-9]{1}["']""",
        WHOLEDOC_CONTENT),
    (
        "email_addresses",                               # store the results in the 'emailaddresses' field
        """[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}""",   # In the whole response content - look for email addresses
        WHOLEDOC_CONTENT),
    (
        "HTML5",
        """<!DOCTYPE html>""",
        WHOLEDOC_TRUEFALSE),
    (
        "jquery",
        ("script", ("src", "href"), """jquery"""),       # SCRIPT tags in SRC & HREF attr - look for the regxp "jquery"
        PARSER_CONTENT),
    (
        "comments",
        """<!--(.*?)-->""",
        WHOLEDOC_CONTENT),
    #(
    #    "ga_docwrites",
    #    """old google analytics doc.writes'""",
    #    WHOLEDOC_CONTENT),
    #(
    #    "Flash_Objects",
    #    """/new[\s]+FlashObject[\s]*\([\s]*['"]?[^'^"]+/""",
    #    WHOLEDOC_COUNT),
    #(
    #    "Flash_Objects",
    #    """/new[\s]+SWFObject[\s]*\([\s]*['"]?[^'^"]+/""",
    #    WHOLEDOC_COUNT),
    #(
    #    "Flash_Objects",
    #    """/\.embedSWF[\s]*\([\s]*["']?[^'^"]+/""",
    #    WHOLEDOC_COUNT
    #)
]
