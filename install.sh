#!/bin/bash

if [ $1 == 'y' ];then
        u="-U"
        y="-y"
else
        u="-u"
fi

clear
# The RAWR banner - sans Dinosaur :\
echo -e "\n\n \`.////.                  .     -+/s.\n s/\`  \`o-   o+\`    -      s.  \`o:  o-\n//   .o\`  \`s/o\`   o.  \`  +:  /+...o/\n \`s\`:+/\`   :o /o-\` :+ .s+\`:+   -/s+/+\n :s:://.  o/:--s-  o.o--o-s   .o. .s\n \`s\`  \`-+ +    \`/: .ss  \`oy\` .o\`  \`s\n  o.     \`          \`\`    .  :-    \`\n\n\tInstallation Script\n\n"

if [ `id -u` != 0 ]; then
        echo -e '  [x] In order to install deps, this script must be run as root.\n'
        exit 1
fi

case `cat /etc/redhat-release 2>/dev/null || cat /etc/issue` in
    *"Kali"* )
            echo -e '\n   [>] Installing Kali Deps\n'
            apt-get install python-qt4 python-pip python-imaging python-lxml python-pygraphviz xvfb $y
            pip install python_qt_binding ;;

    *"Debian"* | *"Ubuntu"* )
            echo -e '\n   [>] Installing Debian Deps\n'
            apt-get install nmap cmake qt4-qmake python python-lxml python-imaging python-psutil python-qt4 python-pip python-netaddr python-lxml python-pygraphviz xvfb $y
            pip install python_qt_binding ;;

    *"ArchAssault"* )
            echo -e '\n   [>]  Installing ArchAssault deps...\n'
            # this is just to fix a broken link
            ln -sf /usr/share/rawr/rawr.py /usr/bin/rawr ;;

    *"Red Hat"* | *"CentOS"* | *"Fedora"* )     
        echo -e '\n   [>] Installing RHEL / CentOS Deps\n'
                
        $epel = 'y'
        if [ $1 != 'y' ]; then    
            read -p '[?] Install and Enable EPEL Repository? [Required]  (Y/n): ' epel

        fi

        if [ "${epel}" != 'n' ]; then
                if grep Fedora /etc/redhat-release; then
                    ver=`sed 's/.*Fedora release \([0-9][0-9]\) .*/\1/' /etc/redhat-release`

                else
                    ver=`sed 's/.*release \(.*\).[0-9] .*/\1/' /etc/redhat-release | cut -d'.' -f1`

                fi
                rpm -Uvh http://mirrors.rit.edu/fedora/epel//epel-release-latest-$ver.noarch.rpm

        else
                echo '[!] EPEL Repo Required - Installation Cancelled.'
                exit 1

        fi

        yum install nmap cmake python python-pip PyQt4 PyQt4 PyQt4-webkit python-argparse python-netaddr python-lxml python-psutil python-imaging python-lxml xorg-x11-server-xvfb $y
        curl "https://bootstrap.pypa.io/get-pip.py" > get-pip.py
        python get-pip.py
        pip install python_qt_binding
        rm -rf get-pip.py

        pgv_deps=" gcc graphviz graphviz-python graphviz-devel python-devel"
        
        $pgv = 'y'
        if [ $1 != 'y' ]; then
            echo '[?] Configuring pygraphviz on Fedora/CentOS/RHEL involves installing the following:'
            echo -e "        $pgv_deps\n"
            read -p '   Would you like to continue? [enables site diagrams during spider] (Y/n): ' pgv

        fi

        if [ "${pgv}" != 'n' ]; then
            yum install $pgv_deps $y            
            wd=`pwd`                
            cd /tmp
            curl https://pypi.python.org/packages/source/p/pygraphviz/pygraphviz-1.3rc2.tar.gz > pgv.tar.gz
            tar -zxvf pgv.tar.gz
            cd pygraphviz-1.3rc2/

            a=""
            if [[ `uname -a` == *"x86_64"* ]]; then a="64"; fi

            sed "s/library\_dirs\ \=\ None/library\_dirs\ \=\'\/usr\/lib$a\/graphviz\'/g" setup.py > setup.py.tmp
            sed "s/include\_dirs\ \=\ None/include\_dirs\ \=\'\/usr\/include\/graphviz\'/g" setup.py.tmp > setup.py
            python setup.py install
            rm setup.py.tmp
            rm -rf pgv.tar.gz
            rm -rf /tmp/pygraphviz-1.3rc2/
            cd $wd

        fi ;;
    
    * ) 
        echo -e "\n   [x] This OS isn't supported by the install script as of yet."
        echo -e "\n         Please let al14s@pdrcorps.com (Twitter - @al14s) know."
        exit 1 ;;

esac

echo -e "\n  [>] Running RAWR update...\n"
"$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"/rawr.py $u -q

echo -e "\n  [+] Installation Finished!\n\n"
