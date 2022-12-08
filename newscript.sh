#!/bin/bash 

startTime=$(date +"%s")
printTime()
{
	endTime=$(date +"%s")
	diffTime=$(($endTime-$startTime))
	if [ $(($diffTime / 60)) -lt 10 ]
	then
		if [ $(($diffTime % 60)) -lt 10 ]
		then
			echo -e "0$(($diffTime / 60)):0$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
		else
			echo -e "0$(($diffTime / 60)):$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
		fi
	else
		if [ $(($diffTime % 60)) -lt 10 ]
		then
			echo -e "$(($diffTime / 60)):0$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
		else
			echo -e "$(($diffTime / 60)):$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
		fi
	fi
}

echo "Are you running this script as sudo?"
select yn in "Yes" "No"; do
	case $yn in
		Yes )  break;;
		No ) exit;;
	esac
done

echo "Creating backup folder and script log"

mkdir -p ~/Desktop/backups
chmod 777 ~/Desktop/backups

touch ~/Desktop/Script.log
echo > ~/Desktop/Script.log
chmod 777 ~/Desktop/Script.log

cp /etc/group ~/Desktop/backups/
cp /etc/passwd ~/Desktop/backups/

echo "Have you configured update policies?"
select yn in "Yes" "No"; do
	case $yn in
		Yes )  break;;
		No ) exit;;
	esac
done

apt-get update && apt-get upgrade -y

echo "Run apt-get dist-upgrade?"
select yn in "Yes" "No"; do
	case $yn in
		Yes )  apt-get dist-upgrade -y -qq; break;;
		No ) break;;
	esac
done

apt-get install gufw -y && ufw enable 

apt-get install clamav -y && cd / && freshclam && clamscan

echo "User Managment Stuff"

echo Type all user account names, with a space in between
read -a users

usersLength=${#users[@]}	

for (( i=0;i<$usersLength;i++))
do
	echo ${users[${i}]}
	echo Delete ${users[${i}]}? yes or no
	read yn1
	if [ $yn1 == yes ]
	then
		userdel -r ${users[${i}]}
		printTime "${users[${i}]} has been deleted."
	else	
		echo Make ${users[${i}]} administrator? yes or no
		read yn2								
		if [ $yn2 == yes ]
		then
			gpasswd -a ${users[${i}]} sudo
			gpasswd -a ${users[${i}]} adm
			gpasswd -a ${users[${i}]} lpadmin
			gpasswd -a ${users[${i}]} sambashare
			printTime "${users[${i}]} has been made an administrator."
		else
			gpasswd -d ${users[${i}]} sudo
			gpasswd -d ${users[${i}]} adm
			gpasswd -d ${users[${i}]} lpadmin
			gpasswd -d ${users[${i}]} sambashare
			gpasswd -d ${users[${i}]} root
			printTime "${users[${i}]} has been made a standard user."
		fi
	fi
done

sleep 5

echo Type user account names of users you want to add, with a space in between
read -a usersNew

usersNewLength=${#usersNew[@]}	

for (( i=0;i<$usersNewLength;i++))
do
	echo ${usersNew[${i}]}
	adduser ${usersNew[${i}]}
	printTime "A user account for ${usersNew[${i}]} has been created."
	echo Make ${usersNew[${i}]} administrator? yes or no
	read ynNew								
	if [ $ynNew == yes ]
	then
		gpasswd -a ${usersNew[${i}]} sudo
		gpasswd -a ${usersNew[${i}]} adm
		gpasswd -a ${usersNew[${i}]} lpadmin
		gpasswd -a ${usersNew[${i}]} sambashare
		printTime "${usersNew[${i}]} has been made an administrator."
	else
		printTime "${usersNew[${i}]} has been made a standard user."
	fi
done

chmod 604 /etc/shadow
printTime "Read/Write permissions on shadow have been set."

chmod 640 .bash_history
printTime "Bash history file permissions set."

echo "Changing User Passwords"

sleep 5

ls /home > users.txt 

awk '{print $0, ":S3cureP@ssw0rd123!"}' users.txt > userspasswds.txt 

sed 's/[[:blank:]]//g' userspasswds.txt > userspasswds2.txt 

chpasswd < userspasswds2.txt 

usermod -L root
echo "Root account has been locked. Use 'usermod -U root' to unlock it."

sleep 3

echo "Inputing Music File Names into Script.log"

find / -name "*.midi" -type f >> ~/Desktop/Script.log
find / -name "*.mid" -type f >> ~/Desktop/Script.log
find / -name "*.mod" -type f >> ~/Desktop/Script.log
find / -name "*.mp3" -type f >> ~/Desktop/Script.log
find / -name "*.mp2" -type f >> ~/Desktop/Script.log
find / -name "*.mpa" -type f >> ~/Desktop/Script.log
find / -name "*.abs" -type f >> ~/Desktop/Script.log
find / -name "*.mpega" -type f >> ~/Desktop/Script.log
find / -name "*.au" -type f >> ~/Desktop/Script.log
find / -name "*.snd" -type f >> ~/Desktop/Script.log
find / -name "*.wav" -type f >> ~/Desktop/Script.log
find / -name "*.aiff" -type f >> ~/Desktop/Script.log
find / -name "*.aif" -type f >> ~/Desktop/Script.log
find / -name "*.sid" -type f >> ~/Desktop/Script.log
find / -name "*.flac" -type f >> ~/Desktop/Script.log
find / -name "*.ogg" -type f >> ~/Desktop/Script.log

find / -name "*.mpeg" -type f >> ~/Desktop/Script.log
find / -name "*.mpg" -type f >> ~/Desktop/Script.log
find / -name "*.mpe" -type f >> ~/Desktop/Script.log
find / -name "*.dl" -type f >> ~/Desktop/Script.log
find / -name "*.movie" -type f >> ~/Desktop/Script.log
find / -name "*.movi" -type f >> ~/Desktop/Script.log
find / -name "*.mv" -type f >> ~/Desktop/Script.log
find / -name "*.iff" -type f >> ~/Desktop/Script.log
find / -name "*.anim5" -type f >> ~/Desktop/Script.log
find / -name "*.anim3" -type f >> ~/Desktop/Script.log
find / -name "*.anim7" -type f >> ~/Desktop/Script.log
find / -name "*.avi" -type f >> ~/Desktop/Script.log
find / -name "*.vfw" -type f >> ~/Desktop/Script.log
find / -name "*.avx" -type f >> ~/Desktop/Script.log
find / -name "*.fli" -type f >> ~/Desktop/Script.log
find / -name "*.flc" -type f >> ~/Desktop/Script.log
find / -name "*.mov" -type f >> ~/Desktop/Script.log
find / -name "*.qt" -type f >> ~/Desktop/Script.log
find / -name "*.spl" -type f >> ~/Desktop/Script.log
find / -name "*.swf" -type f >> ~/Desktop/Script.log
find / -name "*.dcr" -type f >> ~/Desktop/Script.log
find / -name "*.dir" -type f >> ~/Desktop/Script.log
find / -name "*.dxr" -type f >> ~/Desktop/Script.log
find / -name "*.rpm" -type f >> ~/Desktop/Script.log
find / -name "*.rm" -type f >> ~/Desktop/Script.log
find / -name "*.smi" -type f >> ~/Desktop/Script.log
find / -name "*.ra" -type f >> ~/Desktop/Script.log
find / -name "*.ram" -type f >> ~/Desktop/Script.log
find / -name "*.rv" -type f >> ~/Desktop/Script.log
find / -name "*.wmv" -type f >> ~/Desktop/Script.log
find / -name "*.asf" -type f >> ~/Desktop/Script.log
find / -name "*.asx" -type f >> ~/Desktop/Script.log
find / -name "*.wma" -type f >> ~/Desktop/Script.log
find / -name "*.wax" -type f >> ~/Desktop/Script.log
find / -name "*.wmv" -type f >> ~/Desktop/Script.log
find / -name "*.wmx" -type f >> ~/Desktop/Script.log
find / -name "*.3gp" -type f >> ~/Desktop/Script.log
find / -name "*.mov" -type f >> ~/Desktop/Script.log
find / -name "*.mp4" -type f >> ~/Desktop/Script.log
find / -name "*.avi" -type f >> ~/Desktop/Script.log
find / -name "*.swf" -type f >> ~/Desktop/Script.log
find / -name "*.flv" -type f >> ~/Desktop/Script.log
find / -name "*.m4v" -type f >> ~/Desktop/Script.log

find / -name "*.tiff" -type f >> ~/Desktop/Script.log
find / -name "*.tif" -type f >> ~/Desktop/Script.log
find / -name "*.rs" -type f >> ~/Desktop/Script.log
find / -name "*.im1" -type f >> ~/Desktop/Script.log
find / -name "*.gif" -type f >> ~/Desktop/Script.log
find / -name "*.jpeg" -type f >> ~/Desktop/Script.log
find / -name "*.jpg" -type f >> ~/Desktop/Script.log
find / -name "*.jpe" -type f >> ~/Desktop/Script.log
find / -name "*.png" -type f >> ~/Desktop/Script.log
find / -name "*.rgb" -type f >> ~/Desktop/Script.log
find / -name "*.xwd" -type f >> ~/Desktop/Script.log
find / -name "*.xpm" -type f >> ~/Desktop/Script.log
find / -name "*.ppm" -type f >> ~/Desktop/Script.log
find / -name "*.pbm" -type f >> ~/Desktop/Script.log
find / -name "*.pgm" -type f >> ~/Desktop/Script.log
find / -name "*.pcx" -type f >> ~/Desktop/Script.log
find / -name "*.ico" -type f >> ~/Desktop/Script.log
find / -name "*.svg" -type f >> ~/Desktop/Script.log
find / -name "*.svgz" -type f >> ~/Desktop/Script.log

sleep 5

echo "Would you like to automatically configure password policies?"
select yn in "Yes" "No"; do
	case $yn in
		Yes )  cp /etc/login.defs ~/Desktop/backups/; sed -i '160s/.*/PASS_MAX_DAYS\o01130/' /etc/login.defs; sed -i '161s/.*/PASS_MIN_DAYS\o0113/' /etc/login.defs; sed -i '162s/.*/PASS_MIN_LEN\o0118/' /etc/login.defs; sed -i '163s/.*/PASS_WARN_AGE\o0117/' /etc/login.defs; apt-get install libpam-cracklib -y -qq; cp /etc/pam.d/common-auth ~/Desktop/backups/; cp /etc/pam.d/common-password ~/Desktop/backups/; echo -e "#\n# /etc/pam.d/common-auth - authentication settings common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of the authentication modules that define\n# the central authentication scheme for use on the system\n# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the\n# traditional Unix authentication mechanisms.\n#\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\nauth	[success=1 default=ignore]	pam_unix.so nullok_secure\n# here's the fallback if no module succeeds\nauth	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\nauth	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\nauth	optional			pam_cap.so \n# end of pam-auth-update config\nauth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail audit even_deny_root_account silent" > /etc/pam.d/common-auth; echo -e "#\n# /etc/pam.d/common-password - password-related modules common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of modules that define the services to be\n# used to change user passwords.  The default is pam_unix.\n\n# Explanation of pam_unix options:\n#\n# The \"sha512\" option enables salted SHA512 passwords.  Without this option,\n# the default is Unix crypt.  Prior releases used the option \"md5\".\n#\n# The \"obscure\" option replaces the old \`OBSCURE_CHECKS_ENAB\' option in\n# login.defs.\n#\n# See the pam_unix manpage for other options.\n\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\npassword	[success=1 default=ignore]	pam_unix.so obscure sha512\n# here's the fallback if no module succeeds\npassword	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\npassword	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\npassword	optional	pam_gnome_keyring.so \n# end of pam-auth-update config" > /etc/pam.d/common-password;break;;
		No ) exit;;
	esac
done

sleep 3

echo "Purge Malicious Software?"
select yn in "Yes" "No"; do
	case $yn in
		Yes )  apt-get purge wireshark -y; apt-get purge libndpi-wireshark -y; apt-get purge libvirt-wireshark -y; apt-get purge libwireshark-data -y; apt-get purge libwireshark-dev -y; apt-get purge libwireshark11 -y; apt-get purge libwireshark14 -y; apt-get purge libwireshark15 -y; apt-get purge libwireshark16 -y; apt-get purge libwireshark8 -y; apt-get purge wireshark-common -y; apt-get purge wireshark-dev -y; apt-get purge wireshark-doc -y; apt-get purge wireshark-gtk -y; apt-get purge wireshark-qt -y; apt-get purge nmap -y; apt-get purge libnmap-parser-perl -y; apt-get purge nmap-common -y; apt-get purge nmapsi4 -y; apt-get purge python-libnmap -y; apt-get purge python-libnmap-doc -y; apt-get purge python-nmap -y; apt-get purge python3-libnmap -y; apt-get purge python3-nmap -y; apt-get purge zennmap -y; apt-get purge transmission -y; apt-get purge elpa-transmission -y; apt-get purge librust-transmission-client-dev -y; apt-get purge libtransmission-client-perl -y; apt-get purge python-transmissionrpc -y; apt-get purge python-transmissionrpc-doc -y; apt-get purge python3-transmissionrpc -y; apt-get purge transmission-cli -y; apt-get purge transmission-common -y; apt-get purge transmission-daemon -y; apt-get purge transmission-gtk -y; apt-get purge transmission-qt -y; apt-get purge transmission-remote-cli -y; apt-get purge transmission-remote-gtk -y; apt-get purge deluge -y; apt-get purge deluge-common -y; apt-get purge deluge-console -y; apt-get purge deluge-gtk -y; apt-get purge deluge-torrent -y; apt-get purge deluge-web -y; apt-get purge deluge-webgui -y; apt-get purge deluged -y; apt-get purge netcat -y; apt-get purge netcat-openbsd -y; apt-get purge netcat-traditional -y; apt-get purge ncat -y; apt-get purge hydra -y; apt-get purge hydra-gtk -y; apt-get purge aircrack-ng -y; apt-get purge fcrackzip -y; apt-get purge lcrack -y; apt-get purge ophcrack -y; apt-get purge ophcrack-cli -y; apt-get purge pdfcrack -y; apt-get purge pyrit -y; apt-get purge pyrit-opencl -y; apt-get purge rarcrack -y; apt-get purge sipcrack -y; apt-get purge irpas -y; apt-get purge nikto -y; apt-get purge kismet -y; apt-get purge kismet-plugins -y; apt-get purge logkeys -y; apt-get purge zeitgeist-core -y; apt-get purge zeitgeist-datahub -y; apt-get purge python-zeitgeist -y; apt-get purge rhythmbox-plugin-zeitgeist -y; apt-get purge zeitgeist -y; apt-get purge nfs-kernel-server -y; apt-get purge nfs-common -y; apt-get purge portmap -y; apt-get purge rpcbind -y; apt-get purge autofs -y; apt-get purge nginx -y; apt-get purge nginx-common -y; apt-get purge inetd -y; apt-get purge openbsd-inetd -y; apt-get purge xinetd -y; apt-get purge inetutils-ftp -y; apt-get purge inetutils-ftpd -y; apt-get purge inetutils-inetd -y; apt-get purge inetutils-ping -y; apt-get purge inetutils-sylogd -y; apt-get purge inetutils-talk -y; apt-get purge inetutils-talkd -y; apt-get purge inetutils-telnet -y; apt-get purge inetutils-telnetd -y; apt-get purge inetutils-tools -y; apt-get purge inetutils-traceroute-y; apt-get purge vnc4server -y; apt-get purge vncsnapshot -y; apt-get purge vtgrab -y; apt-get purge snmp -y; break;;
		No ) break;;
	esac
done

echo "Finished purges"

sleep 5

echo "Service Managment"

echo Does this machine need Samba?
read sambaYN
echo Does this machine need FTP?
read ftpYN
echo Does this machine need SSH?
read sshYN
echo Does this machine need Telnet?
read telnetYN
echo Does this machine need Mail?
read mailYN
echo Does this machine need Printing?
read printYN
echo Does this machine need MySQL?
read dbYN
echo Will this machine be a Web Server?
read httpYN
echo Does this machine need DNS?
read dnsYN

if [ $sambaYN == no ]
then
	ufw deny netbios-ns
	ufw deny netbios-dgm
	ufw deny netbios-ssn
	ufw deny microsoft-ds
	apt-get purge samba -y -qq
	apt-get purge samba-common -y  -qq
	apt-get purge samba-common-bin -y -qq
	apt-get purge samba4 -y -qq
	printTime "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been denied. Samba has been removed."
elif [ $sambaYN == yes ]
then
	ufw allow netbios-ns
	ufw allow netbios-dgm
	ufw allow netbios-ssn
	ufw allow microsoft-ds
	apt-get install samba -y -qq
	apt-get install system-config-samba -y -qq
	cp /etc/samba/smb.conf ~/Desktop/backups/
	if [ "$(grep '####### Authentication #######' /etc/samba/smb.conf)"==0 ]
	then
		sed -i 's/####### Authentication #######/####### Authentication #######\nsecurity = user/g' /etc/samba/smb.conf
	fi
	sed -i 's/usershare allow guests = no/usershare allow guests = yes/g' /etc/samba/smb.conf
	
	echo Type all user account names, with a space in between
	read -a usersSMB
	usersSMBLength=${#usersSMB[@]}	
	for (( i=0;i<$usersSMBLength;i++))
	do
		echo -e 'Moodle!22\nMoodle!22' | smbpasswd -a ${usersSMB[${i}]}
		printTime "${usersSMB[${i}]} has been given the password 'Moodle!22' for Samba."
	done
	printTime "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been denied. Samba config file has been configured."
else
	echo Response not recognized.
fi
printTime "Samba is complete."

if [ $ftpYN == no ]
then
	ufw deny ftp 
	ufw deny sftp 
	ufw deny saft 
	ufw deny ftps-data 
	ufw deny ftps
	apt-get purge vsftpd -y -qq
	apt-get purge pure-ftpd -y -qq
	printTime "vsFTPd and Pure-FTPD have been removed. ftp, sftp, saft, ftps-data, and ftps ports have been denied on the firewall."
elif [ $ftpYN == yes ]
then
	ufw allow ftp 
	ufw allow sftp 
	ufw allow saft 
	ufw allow ftps-data 
	ufw allow ftps
	cp /etc/vsftpd/vsftpd.conf ~/Desktop/backups/
	cp /etc/vsftpd.conf ~/Desktop/backups/
	gedit /etc/vsftpd/vsftpd.conf&gedit /etc/vsftpd.conf
	service vsftpd restart
	service pure-ftpd
	printTime "ftp, sftp, saft, ftps-data, and ftps ports have been allowed on the firewall. vsFTPd service has been restarted."
else
	echo Response not recognized.
fi
printTime "FTP is complete."

if [ $sshYN == no ]
then
	ufw deny ssh
	apt-get purge openssh-server -y -qq
	printTime "SSH port has been denied on the firewall. Open-SSH has been removed."
elif [ $sshYN == yes ]
then
	apt-get install openssh-server -y -qq
	ufw allow ssh
	cp /etc/ssh/sshd_config ~/Desktop/backups/	
	echo Type all user account names, with a space in between
	read usersSSH
	service ssh restart
	mkdir ~/.ssh
	chmod 700 ~/.ssh
	ssh-keygen -t rsa
	printTime "SSH port has been allowed on the firewall. SSH config file has been configured. SSH RSA 2048 keys have been created."
else
	echo Response not recognized.
fi
printTime "SSH is complete."

if [ $telnetYN == no ]
then
	ufw deny telnet 
	ufw deny rtelnet 
	ufw deny telnets
	apt-get purge telnet -y -qq
	apt-get purge telnetd -y -qq
	apt-get purge inetutils-telnetd -y -qq
	apt-get purge telnetd-ssl -y -qq
	printTime "Telnet port has been denied on the firewall and Telnet has been removed."
elif [ $telnetYN == yes ]
then
	ufw allow telnet 
	ufw allow rtelnet 
	ufw allow telnets
	printTime "Telnet port has been allowed on the firewall."
else
	echo Response not recognized.
fi
printTime "Telnet is complete."

if [ $mailYN == no ]
then
	ufw deny smtp 
	ufw deny pop2 
	ufw deny pop3
	ufw deny imap2 
	ufw deny imaps 
	ufw deny pop3s
	printTime "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been denied on the firewall."
elif [ $mailYN == yes ]
then
	ufw allow smtp 
	ufw allow pop2 
	ufw allow pop3
	ufw allow imap2 
	ufw allow imaps 
	ufw allow pop3s
	printTime "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been allowed on the firewall."
else
	echo Response not recognized.
fi
printTime "Mail is complete."

if [ $printYN == no ]
then
	ufw deny ipp 
	ufw deny printer 
	ufw deny cups
	printTime "ipp, printer, and cups ports have been denied on the firewall."
elif [ $printYN == yes ]
then
	ufw allow ipp 
	ufw allow printer 
	ufw allow cups
	printTime "ipp, printer, and cups ports have been allowed on the firewall."
else
	echo Response not recognized.
fi
printTime "Printing is complete."

if [ $dbYN == no ]
then
	ufw deny ms-sql-s 
	ufw deny ms-sql-m 
	ufw deny mysql 
	ufw deny mysql-proxy
	apt-get purge mysql -y -qq
	apt-get purge mysql-client-core-5.5 -y -qq
	apt-get purge mysql-client-core-5.6 -y -qq
	apt-get purge mysql-common-5.5 -y -qq
	apt-get purge mysql-common-5.6 -y -qq
	apt-get purge mysql-server -y -qq
	apt-get purge mysql-server-5.5 -y -qq
	apt-get purge mysql-server-5.6 -y -qq
	apt-get purge mysql-client-5.5 -y -qq
	apt-get purge mysql-client-5.6 -y -qq
	apt-get purge mysql-server-core-5.6 -y -qq
	printTime "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been denied on the firewall. MySQL has been removed."
elif [ $dbYN == yes ]
then
	ufw allow ms-sql-s 
	ufw allow ms-sql-m 
	ufw allow mysql 
	ufw allow mysql-proxy
	apt-get install mysql-server-5.6 -y -qq
	cp /etc/my.cnf ~/Desktop/backups/
	cp /etc/mysql/my.cnf ~/Desktop/backups/
	cp /usr/etc/my.cnf ~/Desktop/backups/
	cp ~/.my.cnf ~/Desktop/backups/
	if grep -q "bind-address" "/etc/mysql/my.cnf"
	then
		sed -i "s/bind-address\t\t=.*/bind-address\t\t= 127.0.0.1/g" /etc/mysql/my.cnf
	fi
	gedit /etc/my.cnf&gedit /etc/mysql/my.cnf&gedit /usr/etc/my.cnf&gedit ~/.my.cnf
	service mysql restart
	printTime "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been allowed on the firewall. MySQL has been installed. MySQL config file has been secured. MySQL service has been restarted."
else
	echo Response not recognized.
fi
printTime "MySQL is complete."

if [ $httpYN == no ]
then
	ufw deny http
	ufw deny https
	apt-get purge apache2 -y -qq
	rm -r /var/www/*
	printTime "http and https ports have been denied on the firewall. Apache2 has been removed. Web server files have been removed."
elif [ $httpYN == yes ]
then
	apt-get install apache2 -y -qq
	ufw allow http 
	ufw allow https
	cp /etc/apache2/apache2.conf ~/Desktop/backups/
	if [ -e /etc/apache2/apache2.conf ]
	then
  	  echo -e '\<Directory \>\n\t AllowOverride None\n\t Order Deny,Allow\n\t Deny from all\n\<Directory \/\>\nUserDir disabled root' >> /etc/apache2/apache2.conf
	fi
	chown -R root:root /etc/apache2

	printTime "http and https ports have been allowed on the firewall. Apache2 config file has been configured. Only root can now access the Apache2 folder."
else
	echo Response not recognized.
fi
printTime "Web Server is complete."

if [ $dnsYN == no ]
then
	ufw deny domain
	apt-get purge bind9 -qq
	printTime "domain port has been denied on the firewall. DNS name binding has been removed."
elif [ $dnsYN == yes ]
then
	ufw allow domain
	printTime "domain port has been allowed on the firewall."
else
	echo Response not recognized.
fi
printTime "DNS is complete."

echo "Delete files created for passwords?"
select yn in "Yes" "No"; do
	case $yn in
		Yes )  rm /users.txt; rm /userspasswds.txt; rm /userspasswds2.txt; break;;
		No ) break;;
	esac
done

echo "Removing unused packages"

sleep 3

apt-get autoremove -y
apt-get autoclean -y
apt-get clean -y

echo "Complete!"
