#!/bin/bash

if [ $1 == 'y' ];then
	u="-U"
	y="-y"
else
	u="-u"
fi

clear
# The RAWR banner - sans Dinosaur :\
echo -e "\n\n \`.////.                  .     -+/s.\n s/\`  \`o-   o+\`    -      s.  \`o:  o-\n //   .o\`  \`s/o\`   o.  \`  +:  /+...o/\n \`s\`:+/\`   :o /o-\` :+ .s+\`:+   -/s+/+\n :s:://.  o/:--s-  o.o--o-s   .o. .s\n \`s\`  \`-+ +    \`/: .ss  \`oy\` .o\`  \`s\n  o.     \`          \`\`    .  :-    \`\n\n\tInstallation Script\n\n"

if [ `id -u` != 0 ]; then
	echo -e '  [x] In order to install deps, this script must be run as root.\n'
	exit 1
fi

case `cat /etc/issue | cut -d" " -f1 | head -n1` in

	Kali)
		echo -e '\n   [>] Installing Kali Deps\n'
		apt-get install python-qt4 python-pip xvfb python-lxml python-pygraphviz $y
	;;

	Debian)
		echo -e '\n   [>] Installing Debian Deps\n'
		apt-get install cmake qt4-qmake python xvfb python-qt4 python-pip python-netaddr python-lxml python-pygraphviz $y
		pip install python_qt_binding
	;;

	Ubuntu)
		echo -e '\n   [>] Installing Ubuntu Deps\n'
		apt-get install cmake qt4-qmake python xvfb python-qt4 python-pip python-netaddr python-lxml python-pygraphviz $y
		pip install python_qt_binding
	;;

	*)
	echo -e "\n   [!] This OS isn't supported.\n\n"
	exit 1

esac

echo -e "\n  [>] Running RAWR update...\n"
"$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"/rawr.py $u -q

echo -e "\n  [+] Installation Finished!\n\n"

