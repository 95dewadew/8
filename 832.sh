#!/bin/bash
virgo="lost-sa.ga"
myip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
myint=`ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}'`;

flag=0

echo


if [ $USER != 'root' ]; then
	echo "Sorry, for run the script please using root user"
	exit

echo "
AUTOSCRIPT BY DARKSSH
PLEASE CANCEL ALL PACKAGE POPUP
TAKE NOTE !!!"
clear
echo "START AUTOSCRIPT"
clear
echo "SET TIMEZONE JAKARTA GMT +7"
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime;
clear
echo "
ENABLE IPV4 AND IPV6
COMPLETE 1%
"
echo ipv4 >> /etc/modules
echo ipv6 >> /etc/modules
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/g' /etc/sysctl.conf
sysctl -p
clear
echo "
REMOVE SPAM PACKAGE
COMPLETE 10%
"
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove postfix*;
apt-get -y --purge remove bind*;
#apt-get -y --purge remove dropbear*;


echo "
UPDATE AND UPGRADE PROCESS 
PLEASE WAIT TAKE TIME 1-5 MINUTE
"
# install essential package
apt-get -y install build-essential
apt-get -y install screen
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip tar zip unrar rsyslog debsums rkhunter

apt-get -y update;apt-get -y upgrade;apt-get -y install wget curl
echo "
INSTALLER PROCESS PLEASE WAIT
TAKE TIME 5-10 MINUTE
"
# login setting
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells

#text gambar
apt-get install boxes
apt-get -y install make

# squid3
apt-get -y update
apt-get -y install squid3
#wget -O /etc/squid3/squid.conf "$virgo/squid.conf"
echo "http_port 8080" >> /etc/squid3/squid.conf
echo "http_port 8000" >> /etc/squid3/squid.conf
sed -i "s/ipserver/$myip/g" /etc/squid3/squid.conf
chmod 0640 /etc/squid3/squid.conf

# text warna
cd
rm -rf .bashrc
wget $virgo/.bashrc

# text pelangi
apt-get install ruby -y
gem install lolcat

# nginx
apt-get -y install nginx php5-fpm php5-cli
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "$virgo/nginx.conf"
mkdir -p /home/vps/public_html
echo "<pre>Setup by anonym | telegram : UNKNOW | Pin BBM : UNKNOW</pre>" > /home/vps/public_html/index.php
echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
wget -O /etc/nginx/conf.d/vps.conf "$virgo/vps.conf"
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf

# install openvpn
apt-get install openvpn -y
wget -O /etc/openvpn/openvpn.tar "$virgo/openvpn-debian.tar"
cd /etc/openvpn/
tar xf openvpn.tar
wget -O /etc/openvpn/1194.conf "$virgo/1194.conf"
service openvpn restart
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
wget -O /etc/iptables.conf "$virgo/iptables.conf"
sed -i '$ i\iptables-restore < /etc/iptables.conf' /etc/rc.local

myip2="s/ipserver/$myip/g";
sed -i $myip2 /etc/iptables.conf;

iptables-restore < /etc/iptables.conf
service openvpn restart

# configure openvpn client config
cd /etc/openvpn/
wget -O /etc/openvpn/1194-client.ovpn "$virgo/1194-client.conf"
usermod -s /bin/false mail
echo "mail:tester" | chpasswd
useradd -s /bin/false -M tester
echo "tester:id" | chpasswd
cp /etc/openvpn/1194-client.ovpn /home/vps/public_html/
sed -i $myip2 /home/vps/public_html/1194-client.ovpn
sed -i "s/ports/55/" /home/vps/public_html/1194-client.ovpn

# setting port ssh
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
service ssh restart

# encrypt file
wget $virgo/shc-3.8.7.tgz
tar xvfz shc-3.8.7.tgz
cd shc-3.8.7
make && make install
cd

# install dropbear

apt-get -y install dropbear
wget -O /etc/default/dropbear "$virgo/dropbear"
echo "/bin/false" >> /etc/shells
apt-get -y install zlib1g-dev
#wget $virgo/dropbear-2017.75.tar.bz2
#bzip2 -cd dropbear-2017.75.tar.bz2 | tar xvf -
#cd dropbear-2017.75
#./configure
#make && make install
#mv /usr/sbin/dropbear /usr/sbin/dropbear1
#ln /usr/local/sbin/dropbear /usr/sbin/dropbear
#rm dropbear-2017.75.tar.bz2
service ssh restart
service dropbear restart

# bannerssh
wget -O /etc/banner.net "$virgo/bannerssh"
echo -e "Banner /etc/banner.net" >> /etc/ssh/sshd_config
service dropbear restart
service ssh restart

# install fail2ban
apt-get -y install fail2ban
service fail2ban restart

# install webmin
cd
wget http://prdownloads.sourceforge.net/webadmin/webmin_1.820_all.deb
dpkg --install webmin_1.820_all.deb
apt-get -y -f install
rm /root/webmin_1.820_all.deb
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
service webmin restart

# auto reboot 24jam
cd
echo "0 0 * * * root /usr/bin/reboot" > /etc/cron.d/reboot
echo "0 */12 * * * root service dropbear restart" > /etc/cron.d/dropbear
echo "0 0 * * * root ./userexpired.sh" > /etc/cron.d/userexpired
echo "*/30 * * * * root ./clearcache.sh" > /etc/cron.d/clearcache

# tool 
cd
wget -O userlimit.sh "$virgo/userlimit.sh"
wget -O userexpired.sh "$virgo/userexpired.sh"
echo "@reboot root /root/userexpired.sh" > /etc/cron.d/userexpired
chmod +x userexpired.sh
chmod 755 userlimit.sh

# clear cache
wget -O clearcache.sh "$virgo/clearcache.sh"
chmod 755 /root/clearcache.sh

#badvpn
wget -O /usr/bin/badvpn-udpgw "$virgo/badvpn-udpgw"
#chmod 755 /usr/bin/badvpn-udpgw
#badvpn-udpgw --listen-addr 127.0.0.1:7200 > /dev/nul &
sed -i '$ i\badvpn-udpgw --listen-addr 127.0.0.1:7200 > /dev/nul &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200

# buka port 80
iptables -I INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p udp --dport 7200 -j ACCEPT

# speedtest
cd
apt-get install python
wget -O speedtest.py "$virgo/speedtest.py"
chmod +x speedtest.py

# Install Menu
cd
wget "$virgo/nnnn"
mv ./nnnn /usr/bin/menu
chmod +x /usr/bin/menu

wget $virgo/delll
mv ./delll /usr/bin/delll
chmod +x /usr/bin/delll

wget $virgo/user-banned
wget $virgo/user-unbanned
mv ./user-banned /usr/bin/user-banned
mv ./user-unbanned /usr/bin/user-unbanned
chmod +x /usr/bin/user-unbanned
chmod +x /usr/bin/user-banned
wget $virgo/banned-unbanned
mv ./banned-unbanned /usr/bin/banned-unbanned
chmod +x /usr/bin/banned-unbanned
#setting
iptables -t nat -I POSTROUTING -s 192.168.100.0/255.255.255.0 -o eth0 -j MASQUERADE
iptables-save > /etc/iptables.up.rules

#terminal
apt-get -y install unzip
wget https://github.com/KittyKatt/screenFetch/archive/master.zip
unzip master.zip
mv screenFetch-master/screenfetch-dev /usr/bin/sf
chmod 755 /usr/bin/sf

#terminal2
wget $virgo/deb
mv ./deb /usr/bin/deb
chmod +x /usr/bin/deb

# swap ram
dd if=/dev/zero of=/swapfile bs=1024 count=1024k
# buat swap
mkswap /swapfile
# jalan swapfile
swapon /swapfile
#auto star saat reboot
wget $virgo/fstab
mv ./fstab /etc/fstab
chmod 644 /etc/fstab
sysctl vm.swappiness=70
#permission swapfile
chown root:root /swapfile 
chmod 0600 /swapfile

cd
# disable exim
service exim4 stop
sysv-rc-conf exim4 off

rm -rf /etc/cron.weekly/
rm -rf /etc/cron.hourly/
rm -rf /etc/cron.monthly/
rm -rf /etc/cron.daily/
echo "UPDATE AND INSTALL COMPLETE COMPLETE 99% BE PATIENT"
rm $0;rm *.txt;rm *.tar;rm *.deb;rm *.asc
#ddos protect
wget $virgo/ddos.sh
bash ddos.sh
#ssl
wget $virgo/ssl.sh
bash ssl.sh
rm ssl.sh
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
service cron restart
service openvpn restart
service squid3 restart
service ssh restart
service webmin restart
service dropbear restart
service nginx restart
echo " "
echo " "
echo "========================================"  | lolcat
echo "modif by www.darkssh.me" | lolcat 
echo "----------------------------------------" | lolcat
echo ""  | tee -a log-install.txt
echo "Webmin   : http://$myip:10000/" | lolcat
echo "OcsPanel : http://$myip:99/" | lolcat
echo "Squid3   : 8080, 3128" | lolcat
echo "OpenSSH  : 22, 143" | lolcat
echo "Dropbear : 443, 80"| lolcat
echo "OpenVPN  : TCP Port 55" | lolcat
echo "Config   : http://$myip:99/1194-client.ovpn" | lolcat
echo "Timezone : Asia/Jakarta"| lolcat
echo "Fail2Ban : [on]"| lolcat
echo "Power By : darkssh.me"| lolcat
echo ""
echo "Auto kill Multy Login Maximal Login 2"  | lolcat
echo "Auto Install Virtual Ram 1 gb"| lolcat
echo "Tambahan Script: Otomatis Reboot 24 Jam sekali" | lolcat
echo "----------------------------------------"| lolcat
echo "LOG INSTALL  --> /root/log-install.txt"| lolcat
echo "----------------------------------------"| lolcat
echo "----------------------------------------"| lolcat
echo "========================================"  | tee -a log-install.txt
echo "      SILAHKAN REBOOT VPS ANDA !" | lolcat
echo "========================================"  | tee -a log-install.txt
cat /dev/null > ~/.bash_history && history -c
service nginx restart
echo "test" >> /etc/openvpn/log.log
