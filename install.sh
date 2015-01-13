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

case `uname -a` in
	*"kali"* )
		echo -e '\n   [>] Installing Kali Deps\n'
		apt-get install python-qt4 python-pip xvfb python-lxml python-pygraphviz $y ;;

	*"Debian"* )
		echo -e '\n   [>] Installing Debian Deps\n'
		apt-get install nmap cmake qt4-qmake python xvfb python-qt4 python-pip python-netaddr python-lxml python-pygraphviz $y
		pip install python_qt_binding ;;

	*"Ubuntu"* )
		echo -e '\n   [>] Installing Ubuntu Deps\n'
		apt-get install nmap cmake qt4-qmake python xvfb python-qt4 python-pip python-netaddr python-lxml python-pygraphviz $y
		pip install python_qt_binding ;;

	*"archassault"* )
		echo -e '\n   [>]  Installing ArchAssault deps...\n'
		# this is just to fix a broken link
		ln -sf /usr/share/rawr/rawr.py /usr/bin/rawr ;;

	* )
		if [[ `cat /etc/issue` == *"Red Hat"* || `cat /etc/issue` == *"CentOS"* || `cat /etc/issue` == *"Fedora"* ]]; then
			echo -e '\n   [>] Installing RHEL / CentOS Deps\n'
			read -p '[?] Install and Enable EPEL Repository? (y/n): ' epel
			if [ "${epel}" == 'y' ]; then
				ver=`sed 's/.*release \(.*\).[0-9] .*/\1/' /etc/issue | head -n1`

				if [[ `uname -a` == *"x86_64"* ]]; then
					arch="x86_64"

				elif [[ `uname -a` == *"i386"* ]]; then
					arch="i386"

				else
					echo -e "\n    [!] Installer not set up for this architecture - Installation Cancelled."
					echo -e "\n         Please let al14s@pdrcorps.com (Twitter - @al14s) know."
					exit 1

				fi
		
				rpm -Uvh http://download.fedoraproject.org/pub/epel/$ver/$arch/epel-release-6-8.noarch.rpm

			else
			    	echo '[!] EPEL Repo Required - Installation Cancelled.'
				exit 1

			fi

		    	yum install nmap cmake python python-pip PyQt4 PyQt4 PyQt4-webkit python-argparse xvfb python-netaddr python-lxml graphviz $y
		       	curl "https://bootstrap.pypa.io/get-pip.py" > get-pip.py
			python get-pip.py
		       	pip install python_qt_binding pygraphviz
			rm -rf get-pip.py

		else
			echo -e "\n   [x] This OS isn't supported by the install script as of yet."
			echo -e "\n         Please let al14s@pdrcorps.com (Twitter - @al14s) know."
			exit 1

		fi	

esac

echo -e "\n  [>] Running RAWR update...\n"
"$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"/rawr.py $u -q

echo -e "\n  [+] Installation Finished!\n\n"

