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

if [[ `uname -a` == *"Kali"* ]]; then
	echo -e '\n   [>] Installing Kali Deps\n'
	apt-get install python-qt4 python-pip xvfb python-lxml python-pygraphviz $y

elif [[ `uname -a` == *"Debian"* ]]; then
	echo -e '\n   [>] Installing Debian Deps\n'
	apt-get install cmake qt4-qmake python xvfb python-qt4 python-pip python-netaddr python-lxml python-pygraphviz $y
	pip install python_qt_binding

elif [[ `uname -a` == *"Ubuntu"* ]]; then
	echo -e '\n   [>] Installing Ubuntu Deps\n'
	apt-get install cmake qt4-qmake python xvfb python-qt4 python-pip python-netaddr python-lxml python-pygraphviz $y
	pip install python_qt_binding

elif [[ `uname -a` == *"archassault"* ]]; then
	echo -e '\n   [>]  Installing ArchAssault deps...\n'
	# fix a broken link
	ln -sf /usr/share/rawr/rawr.py /usr/bin/rawr

elif [[ `cat /etc/issue | cut -d" " -f1,2 | head -n1` == 'Red Hat' ]]; then
        echo -e '\n   [>] Installing Red Hat Deps\n'
        read -p '[?] Install and Enable EPEL Repository? (y/n): ' epel
        if [ "${epel}" == 'y' ]; then
                rpm -Uvh http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm

        else
            	echo '[!] Installation Cancelled.'
                exit 1

	fi

    	yum install cmake python python-pip PyQt4 PyQt4 PyQt4-webkit python-argparse xvfb python-netaddr python-lxml graphviz $y
       	curl "https://bootstrap.pypa.io/get-pip.py" > get-pip.py
        python get-pip.py
       	pip install python_qt_binding pygraphviz
	rm -rf get-pip.py

elif [[ `cat /etc/issue | cut -d" " -f1 | head -n1` == 'CentOS' ]]; then
	echo -e '\n   [>] Installing CentOS Deps\n'
	read -p '[?] Install and Enable EPEL Repository? (y/n): ' epel
	if [ "${epel}" == 'y' ]; then
		rpm -ivh http://linux.mirrors.es.net/fedora-epel/6/i386/epel-release-6-8.noarch.rpm

	else
		echo '[!] Installation Cancelled.'
		exit 1

	fi

	yum install cmake python python-pip PyQt4 PyQt4 PyQt4-webkit python-argparse xvfb python-netaddr python-lxml graphviz $y
	curl "https://bootstrap.pypa.io/get-pip.py" > get-pip.py
	python get-pip.py
	pip install python_qt_binding pygraphviz
	rm -rf get-pip.py

else
	echo -e "\n   [x] This OS isn't supported by the install script as of yet."
	echo -e "\n         Please let al14s@pdrcorps.com know."
	exit 1

fi

echo -e "\n  [>] Running RAWR update...\n"
"$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"/rawr.py $u -q

echo -e "\n  [+] Installation Finished!\n\n"

