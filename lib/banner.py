from lib.constants import VERSION, TCOLORS

m = m2 = (29 - len(VERSION))/2
if len(VERSION) % 2 == 0:
    m += 1

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
   """ + TCOLORS.BLUE + "Rapid Assessment of Web Resources" + TCOLORS.END + """   dd  .h/hyhddMms+:-/./m   dy-
                                       /M-  -NmmNhms`     ``m`  sd.;.
%s[Version %s]%s`Ms   mNmNN+       s/y   oNoyM:
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

""" % (" " * m, VERSION, " " * m2)

usage = """
 ./rawr.py
        [-n <range>|-i <list> (-p <ports> -s <src port> -t <timing>)|-f <file>]
             [-d <dir>] [--sslv] [-aboqrvxz] [--downgrade] [--noss]
           [--proxy <ip:port>] [-m] [--sqlite] [--json] [--json-min]
          [--spider] [--spider-opts <opts>] [--alt-domains <domains>]
                    [-e] [--title <title>] [--logo <file>]
           [--parsertest] [-u|-U] [--check-install|--force-install]"""

words = "Random,Ragged,Rabid,Rare,Radical,Rational,Risky,Remote,Rowdy,Rough,Rampant,Ruthless:Act,Audit,Arming,Affront,Arc,Attack,Apex,Assault,Answer,Assembly,Attempt,Alerting,Arrest,Account,Apparel,Approval,Army:Wily,Weird,Wonky,Wild,Wascawy,Wimpy,Winged,Willing,Working,Warring,Wacky,Wasteful,Wealthy,Worried:Ravioli,Rats,Rabbits,Rhinos,Robots,Rigatoni,Reindeer,Roosters,Robins,Raptors,Raccoons,Reptiles"
