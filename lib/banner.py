
from lib.constants import VERSION

banner = """             
                                                    , `.
 `.////.                  .     -+/s.            +ho+oo-o`
 s/`  `o-   o+`    -      s.  `o:  o-         -sddo//+sydhys/:'.
 //   .o`  `s/o`   o.  `  +:  /+...o/      .smd+.   `/o+.`-ymoo,
 `s`:+/`   :o /o-` :+ .s+`:+   -/s+/+    `omy-     :mh-om/  -dh//:.
  :s:://.  o/:--s-  o.o--o-s   .o. .s   `hh.       hddydNy    od.o /
  `s`  `-+ +    `/: .ss  `oy` .o`  `s  `ds  -.     `+yhy+`     od-.
   o.     `          ``    .  :-    `  ym `moy.   `..-:///:/` `N/-
                                      :M+ .yhy+-.,/:--/o\ /d`  om/`',
                                      -M:  .'-/+:symdyysy+oN+  .N+:-
   Rapid Assessment of Web Resources   dd  .h/hyhddMms+:-/./m   dy-
                                       /M-  -NmmNhms`     ``m`  sd.;.
            [Version %s]            `Ms   mNmNN+       s/y   oNoyM:
                                   ,os+-mh   /mymm :./+:/+s+/ :hs``mM-
                                   +y.:omN`  -o:dso/o:+::.   `oh-  +My
                                    /h:`oM-                  ``   :Nd
                                     .yyyM/                     `+Nh`
         by Adam Byers (@al14s)        -hMo     .:++:/.         `/hm::
                                        .Ny   .o/-------.         oN:-
           al14s@pdrcorps.com           `Ny   s..`..-...+ `/+     :N/-:`
                                       `oMy   o.`....```-/h/.    `-:ooy/-:`
                                       d/Ny   /...``...//N`           `:+o:.-
                                      .N`N/   ./.`.----:sd                 -/o
                                     oo/.d-  `./-o+++-:mh/.```:-````-:+sys+:.

""" % VERSION

usage = """
 Usage: 
   ./rawr.py [-n <range> (-p <ports> -s <port> -t <timing>)|-f <xml>|-i <list>]
                   [-d <dir>] [--sslv] [-aboqrz] [--downgrade] [--spider]
                     [-e] [--title <title>] [--logo <file>]
                    [-u|-U] [--check-install|--force-install]

   INPUT/SCAN OPTIONS:
    -a      Include all open ports in .csv, not just web interfaces.
    -f      NMap|Nessus|Nexpose|Qualys xml or dir from which to pull files.
    -i      Target an input list.  [NMap format] [can't be used with -n]
    -n      Target the specified range or host.  [NMap format]
    -p      Specify port(s) to scan.   [default is '80,443,8080,8088']
    -s      Specify a source port for the NMap scan.
    -t      Set a custom NMap scan timing.   [default is 4]
    --sslv  Assess the SSL security of each target.  [considered intrusive]


   ENUM OPTIONS:
    -b      Use Bing to gather external hostnames. (good for shared hosting)
    -o      Make an 'OPTIONS' call to grab the site's available methods.
    -r      Make an additional web call to get 'robots.txt'
    --downgrade  Make requests using HTTP 1.0
    --spider     Enumerate all urls in target's HTML, create site layout
                 graph.  Will record but not follow links outside of the
                 target's domain.  Creates a map (.png) for that site in 
                 the <logfolder>/maps folder.


   OUTPUT OPTIONS:
    -d      Directory in which to create log folder [default is './']
    -h      Show this info + summary + examples.
    -q      'quiet' - Won't show splash screen.
    -z      Compress log folder when finished.


   REPORT OPTIONS:
    -e       Exclude default username/password data from output.
    --title  Specify a custom title for the HTML report.
    --logo   Specify a logo file for the HTML report.


   UPDATE OPTIONS:
    -u      Check for newer version of IpToCountry.csv and defpass.csv.
    -U      Force update of IpToCountry.csv and defpass.csv.

    --check-install  Check for newer IpToCountry.csv and defpass.csv,
                     Check for presence of NMap and its version.
                     Check for presence of phantomJS, prompts if installing.

    --force-install  Force update - IpToCountry.csv, defpass,csv, phantomJS.
                     Check for presence of NMap and its version.
"""

summary = """

   SUMMARY:

         Uses NMap, Qualys, Nexpose, or Nessus scan data to target web
             services for enumeration. Visits each host on each port with an
             identified web service and gathers as much data as possible.  


         Output:  
              All NMap output formats (xml uses local copy of nmap.xsl)
              CSV worksheet containing all collected info.
              HTML report  (searchable, jQuery-driven, standalone)
              Images folder  (contains screenshots of the web interfaces)
              Cookies folder
              SSL Certificates folder

         Usage diagram:

         .--LOG          --.   .--SCAN                           --.
         | ./log_[dt]_rawr/ |  | -a include all results in csv     |
         | -z .tar file      > | -f nmap or nessus xml (or dir)    |
         | -d log directory |  | -i use an input list for NMap     |
         `--              --'  | -n nmap <range>                    >[xml data]
                               |     (-p <ports>,-t <timing>)      |      .
                               |      (-s <source port>)           |      |
                               | --sslv [intrusive] SSL assessment |      |
                               `--                               --'      |
                                    .-------------------------------------'
                                    |
         .--SUPPLEMENT         --.  |   .--ENUMERATE                     --.
         | IpToCountry.csv &     |  `-> | --spider  enum links from pages  |
         |   defpass.csv         |      | --downgrade  use HTTP 1.0         --.
         | -u|-U to update from   ----> | -o Pull available methods        |  |
         |    the SF page or     |      | -r make call for robots.txt      |  |
         | -e to exclude defpass |      `--                              --'  |
         | -b use Bing for DNS   |                                            |
         | --title report title  |          .---------------------------------`
         | --logo  report logo   |          |
         `--                   --'          |   .--OUTPUT      --.
                                            |   | CSV worksheet  |
                                            |   | HTML report    |
                                            `-> | NMap output     >    :)
                                                | Cookies        |
                                                | Screenshots    |
                                                | SSL certs      |
                                                | Site crawl PNG |
                                                | Robots.txt     |
                                                `--            --'"""        

examples = """


   EXAMPLES:

     ./rawr.py -n scanme.nmap.org --spider
          Create log folders in current directory [./log_<date>_<time>_rawr/]
          Follow and enumerate links in the target's HTML as long as
            they're in the target's domain.  
          Will create a map of the site in the maps folder.

     ./rawr.py -n www.google.com -p all
          Pull data from web services found on any of the 65535 ports.

     ./rawr.py -f previous_nmap_scan.xml --sslv
          Use targets from a previous nmap scan, assessing the server's
            SSL security state.

     ./rawr.py -d scanfolder -n scanme.nmap.org -p 80,8080 -e
          Pull additional data about the server/site and its SSL cert from
            ports 80 and 8080, excluding default password data.  
            Stores results in ./scanfolder/log_<date>_<time>_rawr/ .

     ./rawr.py -i nmap_inputlist.iL -p fuzzdb -b -z
          Use an input list, checking the fuzzdb 'common web ports'.  
            Compress results into a .tar file.
            Use Bing to resolve DNS names of hosts.

     ./rawr.py -u
          Update 'Ip to Country' and 'default password' lists from the
            BitBucket repo.


"""
