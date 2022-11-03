#!/bin/bash 

echo "Are you running this script as sudo?"
select yn in "Yes" "No"; do
	case $yn in
		Yes )  break;;
		No ) exit;;
	esac
done

apt update && apt upgrade -y 

apt install gufw -y && ufw enable 

apt install clamav -y && cd / && freshclam && clamscan

apt install libpam-cracklib -y 

echo "Changing User Passwords"

sleep 3

ls /home > users.txt 

awk '{print $0, ":S3cureP@ssw0rd123!"}' users.txt > userspasswds.txt 

sed 's/[[:blank:]]//g' userspasswds.txt > userspasswds2.txt 

chpasswd < userspasswds2.txt 

passwd -l root 

echo "Finding .mp3s"

echo "You have mp3s in the following directories..."

find / -name *.mp3

sleep 5

echo "Have you configured password policies?"
select yn in "Yes" "No"; do
	case $yn in
		Yes )  break;;
		No ) exit;;
	esac
done

echo "Attempting to purge WireShark, nmap, John the Ripper, telnet, Hydra"

sleep 5

apt purge wireshark -y
apt purge nmap -y
apt purge zenmap -y
apt purge john -y
apt purge telnet -y
apt purge hydra -y
apt purge hydra-gtk -y

echo "Finished attempting purges"

sleep 3

echo "Complete!"
