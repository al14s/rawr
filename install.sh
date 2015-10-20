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
		apt-get install python-qt4 python-pip python-imaging python-lxml python-pygraphviz $y
	    [ `which Xorg` ] || {
                                echo -e '\n   [>] This appears to be a headless server, installing xvfb.\n'
                                apt-get install xvfb $y
                            } || {
                                echo -e "\n\n  [x] Error installing xvfb."
                                echo -e "\tPlease ensure that kali-rolling is in sources.list .\n\n"
                                exit 1
                            } ;;

	*"Debian"* )
		echo -e '\n   [>] Installing Debian Deps\n'
		apt-get install nmap cmake qt4-qmake python python-imaging python-psutil python-qt4 python-pip python-netaddr python-lxml python-pygraphviz $y
	    [ `which Xorg` ] || {
                                echo -e '\n   [>] This appears to be a headless server, installing xvfb.\n'
                                apt-get install xvfb $y
                            } || {
                                echo -e "\n\n  [x] Error installing xvfb.\n\n"
                                exit 1
                            }
		pip install python_qt_binding ;;

	*"Ubuntu"* )
		echo -e '\n   [>] Installing Ubuntu Deps\n'
		apt-get install nmap cmake qt4-qmake python python-imaging python-psutil python-qt4 python-pip python-netaddr python-lxml python-pygraphviz $y
	    [ `which Xorg` ] || {
                                echo -e '\n   [>] This appears to be a headless server, installing xvfb.\n'
                                apt-get install xvfb $y
                            } || {
                                echo -e "\n\n  [x] Error installing xvfb.\n\n"
                                exit 1
                            }
		pip install python_qt_binding ;;

	*"archassault"* )
		echo -e '\n   [>]  Installing ArchAssault deps...\n'
		# this is just to fix a broken link
		ln -sf /usr/share/rawr/rawr.py /usr/bin/rawr ;;

	* )
        if [[ `cat /etc/redhat-release` == *"Red Hat"* || `cat /etc/issue` == *"Red Hat"* || `cat /etc/issue` == *"CentOS"* || `cat /etc/issue` == *"Fedora"* ]]; then
	        echo -e '\n   [>] Installing RHEL / CentOS Deps\n'
	        read -p '[?] Install and Enable EPEL Repository? (y/n): ' epel
	        if [ "${epel}" == 'y' ]; then
		        ver=`sed 's/.*release \(.*\).[0-9] .*/\1/' /etc/issue | head -n1`

		        if [[ `uname -a` == *"x86_64"* ]]; then
			        arch="x86_64"; a="64"

		        elif [[ `uname -a` == *"i386"* ]]; then
			        arch="i386"; a=""

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

            yum install nmap cmake python python-pip PyQt4 PyQt4 PyQt4-webkit python-argparse python-netaddr python-lxml python-psutil python-imaging python-lxml $y
	        [ `which Xorg` ] || {
                                    echo -e '\n   [>] This appears to be a headless server, installing xvfb.\n'
                                    yum install xvfb $y
                                }
            curl "https://bootstrap.pypa.io/get-pip.py" > get-pip.py
            python get-pip.py
            pip install python_qt_binding
            rm -rf get-pip.py

            pgv_deps=" gcc graphviz graphviz-python graphviz-devel python-devel"
            echo '[?] Configuring pygraphviz on Fedora/CentOS/RHEL involves installing the following:'
            echo -e "        $pgv_deps\n"
            read -p '   Would you like to continue? [enables site diagrams during spider] (y/n): ' pgv
            if [ "${pgv}" == 'y' ]; then
                yum install $pgv_deps $y            
                wd=`pwd`                
                cd /tmp
                curl https://pypi.python.org/packages/source/p/pygraphviz/pygraphviz-1.3rc2.tar.gz > pgv.tar.gz
                tar -zxvf pgv.tar.gz
                cd pygraphviz-1.3rc2/
                sed "s/library\_dirs\ \=\ None/library\_dirs\ \=\'\/usr\/lib$a\/graphviz\'/g" setup.py > setup.py.tmp
                sed "s/include\_dirs\ \=\ None/include\_dirs\ \=\'\/usr\/include\/graphviz\'/g" setup.py.tmp > setup.py
                python setup.py install
                rm setup.py.tmp
                rm -rf pgv.tar.gz
                rm -rf /tmp/pygraphviz-1.3rc2/
                cd $wd

            fi

        else
	        echo -e "\n   [x] This OS isn't supported by the install script as of yet."
	        echo -e "\n         Please let al14s@pdrcorps.com (Twitter - @al14s) know."
	        exit 1

        fi	

esac

echo -e "\n  [>] Running RAWR update...\n"
"$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"/rawr.py $u -q

echo -e "\n  [+] Installation Finished!\n\n"

