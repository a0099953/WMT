#! /bin/bash
d=`date +"%d-%m-%y"`
h=`hostname`
mkdir -p /bkp
OPTIONS="HARDEN ROLLBACK Quit"
select opt in $OPTIONS;
do
if [ $opt = HARDEN ]; then
########## Ensure root is the only UID 0 Account ##########
echo -e "TASK 2\t:Ensure root is the only UID 0 Account. Find status below\n"
uniqid=`awk -F":" '{if ($3 == 0) print $1}' /etc/passwd |wc -l`
if [ $uniqid = 1 ];then
echo "Only root is using uid 0"
else
echo "UID 0 is shared with multiple users.Users are \n `awk -F":" '{if ($3 == 0) print $1}' /etc/passwd`"
fi
######## Ensure default group for the root account is GID 0 ########
echo -e "TASK 3\t:Ensure default group for the root account is GID 0. Find status below\n"
uniqgid=`grep root /etc/passwd |awk -F":" '{print $4}'`
if [ $uniqgid = 0 ];then
echo -e "Root GID is\t:\t0 "
else
echo -e "Root User GID is not 0. the present GID is\t:\t$uniqgid"
fi

######### Ensure default user umask is 027 or more restrictive ############
echo -e "TASK 4\t:Ensure default user umask is 027 or more restrictive. Find status below\n"
cp -r /etc/login.defs /bkp/login.defs-$d-$h.bkp
sed -i "s/^UMASK/#UMASK/g" /etc/login.defs
sed -i "/#UMASK/a UMASK          027" /etc/login.defs
um=` grep UMASK /etc/login.defs | grep -v ^# | awk '{print $2}'`
if [ $um = 027 ];then
echo -e "UMASK has been set as per requirement i.e 027"
chmod 750 /home/*
else
echo "Something wrong above commands not able to change UMASK. Kindly verify file status"
fi

######### Filesystem Integrity Checking  ##################
echo -e "TASK 5\t:Filesystem Integrity Checking has been enabled for all file systems now\n"
cp -r /etc/fstab /bkp/fstab-$d-$h.bkp
sed -i -r 's/(\s+)?\S+//6' /etc/fstab
sed -i 's/$/ 1/' /etc/fstab


######### Ensure cron daemon is enabled ################
echo -e "TASK 6\t:Ensure cron daemon is enabled. Find status below\n"
cs0=`systemctl is-enabled cron`
cs1=`systemctl status cron | grep Active |awk '{print $3}' | tr -d "()"`
if [ $cs0 = enabled -a $cs1 = running ];then
echo " cron service is enabled and running "
else
systemctl enable cron && systemctl restart cron
if [ $? = 0 ];then
echo "cron service has been started now and enabled permanently"
else
echo " cron service not able to start. Login to server and start it manually"
fi
fi

######## SSH parameters #############

cp /etc/ssh/sshd_config /bkp/sshd_config-$d-$h.bkp
sed -i '/Protocol 2/s/^#//g' /etc/ssh/sshd_config
sed -i '/PermitRootLogin yes/s/^#//g' /etc/ssh/sshd_config
sed -i -e 's|PermitRootLogin yes|PermitRootLogin no|g' /etc/ssh/sshd_config
sed -i "/X11Forwarding no/s/^#//g" /etc/ssh/sshd_config
sed -i "s/X11Forwarding yes/X11Forwarding no/g" /etc/ssh/sshd_config
sed -i "/AllowTcpForwarding no/s/^#//g" /etc/ssh/sshd_config
sed -i "s/AllowTcpForwarding yes/AllowTcpForwarding no/g" /etc/ssh/sshd_config
sed -i "/IgnoreRhosts/s/^#//g" /etc/ssh/sshd_config
sed -i "/#HostbasedAuthentication no/s/^#//g" /etc/ssh/sshd_config
sed -i "/PermitEmptyPasswords/s/^#//g" /etc/ssh/sshd_config
sed -i "/PermitUserEnvironment/s/^#//g" /etc/ssh/sshd_config
sed -i "/ClientAliveInterval/s/^#//g" /etc/ssh/sshd_config
sed -i "/ClientAliveCountMax/s/^#//g" /etc/ssh/sshd_config
sed -i "s/ClientAliveInterval 0/ClientAliveInterval 300/g" /etc/ssh/sshd_config
sed -i "s/ClientAliveCountMax 3/ClientAliveCountMax 0/g" /etc/ssh/sshd_config
systemctl reload sshd
echo -e "TASK 7\t:Ensure SSH root login is disabled\t : completed\n"
echo -e "TASK 8\t:Ensure SSH Protocol is set to 2\t : completed\n"
echo -e "TASK 9\t:Ensure SSH X11 forwarding is disabled\t : completed\n"
echo -e "TASK 10\t:Ensure SSH MaxAuthTries is set to 4 or less\t : completed\n"
echo -e "TASK 11\t:Ensure SSH IgnoreRhosts is enabled\t : completed\n"
echo -e "TASK 12\t:Ensure SSH HostbasedAuthentication is disabled\t : completed\n"
echo -e "TASK 13\t:Ensure SSH PermitEmptyPasswords is disabled\t : completed\n"
echo -e "TASK 14\t:Ensure SSH PermitUserEnvironment is disabled\t : completed\n"
echo -e "TASK 15\t:Ensure SSH Idle Timeout Interval is configured\t : completed\n"
echo -e "TASK 16\t:Ensure SSH LoginGraceTime is set to one minute or less\t : completed\n"



############ Set Shadow Password Suite Parameters ####################
sed -i "s/^PASS_MAX_DAYS/#PASS_MAX_DAYS/g" /etc/login.defs
sed -i "/#PASS_MAX_DAYS/a PASS_MAX_DAYS   60" /etc/login.defs
sed -i "s/^PASS_MIN_DAYS/#PASS_MIN_DAYS/g" /etc/login.defs
sed -i "/#PASS_MIN_DAYS/a PASS_MIN_DAYS   2" /etc/login.defs
sed -i "s/^PASS_WARN_AGE/#PASS_WARN_AGE/g" /etc/login.defs
sed -i "/#PASS_WARN_AGE/a PASS_WARN_AGE   7" /etc/login.defs
cp -r /etc/default/useradd /bkp/useradd-$d-$h.bkp
sed -i "s/INACTIVE/# INACTIVE/g" /etc/default/useradd
sed -i "/# INACTIVE/a INACTIVE=30" /etc/default/useradd
echo -e "TASK 17\t:Ensure password expiration is 60 days or less\t : completed\n"
echo -e "TASK 18\t:Ensure minimum days between password changes is 2 or more\t : completed\n"
echo -e "TASK 19\t:Ensure password expiration warning days is 7 or more\t : completed\n"
echo -e "TASK 20\t:Ensure inactive password lock is 30 days or less\t : completed\n"

######### Xinetd related ########################

chkconfig chargen-dgram off
chkconfig chargen-stream off
chkconfig daytime-dgram off
chkconfig daytime-stream off
chkconfig discard off
chkconfig discard-udp off
chkconfig echo-dgram off
chkconfig echo-stream off
chkconfig time off
chkconfig time-udp off
systemctl disable telnet.socket

echo -e "TASK 21\t:Ensure chargen services are not enabled\t : completed\t find status below\n"
chargen=`grep disable /etc/xinetd.d/chargen | awk -F"=" '{print $2}'`
if [ $chargen = yes ];
then
echo "chargen service already disabled"
else
cp -r /etc/xinetd.d/chargen /bkp/chargen-$d-$h.bkp
sed -i 's/disable/# disable/g' /etc/xinetd.d/chargen
sed -i "/# disable/a disable   = yes" /etc/xinetd.d/chargen 
echo "chargen has been disabled now"
fi

echo -e "TASK 22\t:Ensure daytime services are not enabled\t : completed\t find status below\n"
dtime=`grep disable /etc/xinetd.d/daytime | awk -F"=" '{print $2}'`
if [ $dtime = yes ];
then
echo "Daytime service already disabled"
else
cp -r /etc/xinetd.d/daytime /bkp/daytime-$d-$h.bkp
sed -i 's/disable/# disable/g' /etc/xinetd.d/daytime
sed -i "/# disable/a disable   = yes" /etc/xinetd.d/daytime 
echo "Daytime has been disabled now"
fi
echo -e "TASK 23\t:Ensure discard services are not enabled\t : completed\t find status below\n"
dis=`grep disable /etc/xinetd.d/discard | awk -F"=" '{print $2}'`
if [ $dis = yes ];
then
echo "Discard service already disabled"
else
cp -r /etc/xinetd.d/discard /bkp/discard-$d-$h.bkp
sed -i 's/disable/# disable/g' /etc/xinetd.d/discard
sed -i "/# disable/a disable   = yes" /etc/xinetd.d/discard 
echo "discard has been disabled now"
fi
echo -e "TASK 24\t:Ensure echo services are not enabled\t : completed\t find status below\n"
ec=`grep disable /etc/xinetd.d/echo | awk -F"=" '{print $2}'`
if [ $ec = yes ];
then
echo "Echo service already disabled"
else
cp -r /etc/xinetd.d/echo /bkp/echo-$d-$h.bkp
sed -i 's/disable/# disable/g' /etc/xinetd.d/echo
sed -i "/# disable/a disable   = yes" /etc/xinetd.d/echo 
echo "Echo has been disabled now"
fi

echo -e "TASK 25\t:Ensure time services are not enabled\t : completed\t find status below\n"
tm=`grep disable /etc/xinetd.d/time | awk -F"=" '{print $2}'`
if [ $tm = yes ];
then
echo "Time service already disabled"
else
cp -r /etc/xinetd.d/time /bkp/time-$d-$h.bkp
sed -i 's/disable/# disable/g' /etc/xinetd.d/time
sed -i "/# disable/a disable   = yes" /etc/xinetd.d/time 
echo "Time has been disabled now"
fi

###### Ensure prelink is disabled ########
echo -e "TASK 26\t:Ensure prelink is disabled\t : completed\n"
zypper  --non-interactive remove prelink
###### Ensure DCCP is disabled ######### 
echo -e "TASK 27\t:Ensure DCCP is disabled \t : completed - \t find status below\n"
nohup modprobe -n -v dccp > /tmp/o.txt
dccp=`grep FATAL /tmp/o.txt |wc -l`
dccp1=`grep "insmod" /tmp/o.txt|wc -l`
if [ $dccp = 1 ];
then
echo " DCCP is not installed in this machine"
elif [ $dccp1 = 1 ];
then
echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
echo " DCCP has been is disabled now"
fi

####### Ensure SCTP is disabled ########
echo -e "TASK 27\t:Ensure SCTP is disabled\t : completed\t find status below\n"
nohup modprobe -n -v sctp > /tmp/o.txt
sctp=`grep FATAL /tmp/o.txt |wc -l`
sctp1=`grep "insmod" /tmp/o.txt|wc -l`
if [ $sctp = 1 ];
then
echo " SCTP is not installed in this machine"
elif [ $sctp1 = 1 ];
then
echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
echo " SCTP has been is disabled now"
fi

####### Ensure RDS is disabled ########
echo -e "TASK 28\t:Ensure RDS is disabled\t : completed\t find status below\n"
nohup modprobe -n -v rds > /tmp/o.txt
rds=`grep FATAL /tmp/o.txt |wc -l`
rds1=`grep "insmod" /tmp/o.txt|wc -l`
if [ $rds = 1 ];
then
echo " RDS is not installed in this machine"
elif [ $rds1 = 1 ];
then
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
echo " RDS has been is disabled now"
fi
####### Ensure TIPC is disabled ########
echo -e "TASK 29\t:Ensure TIPC is disabled\t : completed\t find status below\n"
nohup modprobe -n -v tipc > /tmp/o.txt
tipc=`grep FATAL /tmp/o.txt |wc -l`
tipc1=`grep "insmod" /tmp/o.txt|wc -l`
if [ $tipc = 1 ];
then
echo " TIPC is not installed in this machine"
elif [ $tipc1 = 1 ];
then
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
echo " TIPC has been is disabled now"
fi
####### Ensure IPv6 is disabled #########
echo -e "TASK 30\t:Ensure IPv6 is disabled\t : completed\t find status below\n"
iv=`modprobe -c | grep "options ipv6" |wc -l`
if [ "$iv" = "0" ];
then
echo " IPV6 is not enabled in this machine"
elif [ "$iv" = "1" ];
then
echo "options ipv6 disable=1" >> /etc/modprobe.d/CIS.conf
echo " IPV6 has been is disabled now"
fi

####### Ensure TCP Wrappers is installed #######
echo -e "TASK 31\t:Ensure TCP Wrappers is installed\t : completed\t find status below\n"
tcw=`rpm -qa | grep "^netcfg" |wc -l`
if [ $tcw = 0 ];then
zypper --non-interactive install netcfg
echo "Tcp Wrapper has been installed now"
else
echo "Tcp wrapper already installed"
fi
######  Ensure /etc/hosts.allow and /etc/hosts.deny is configured #######
echo -e "TASK 32\t:Ensure /etc/hosts.allow\t : completed\n"
echo -e "TASK 33\t:Ensure /etc/hosts.deny\t : completed\n"
sed -i 's/^/#/' /etc/hosts.allow
sed -i 's/^/#/' /etc/hosts.deny
sed -i 's/^##/#/g' /etc/hosts.allow
sed -i 's/^##/#/g' /etc/hosts.deny
echo " /etc/hosts.allow and /etc/hosts.deny is configured"
####### Ensure iptables is installed ######
echo -e "TASK 34\t:Ensure iptables is installed\t : completed\t find status below\n"
ipt=`rpm -qa | grep "^iptables" |wc -l`
if [ $ipt = 0 ];then
zypper --non-interactive install iptables
echo "Iptables has been installed now"
else
echo "Iptables already installed"
fi
####### Ensure rsyslog or syslog-ng is installed #########
echo -e "TASK 35\t:Ensure rsyslog or syslog-ng is installed\t : completed\t find status below\n"
rsy=`rpm -qa | grep "^rsyslog" |wc -l`
if [ $rsy = 0 ];then
zypper --non-interactive install rsyslog
echo "Rsyslog has been installed now"
else
echo "Rsyslog already installed"
fi

####### Ensure tftp server is not enabled #########
echo -e "TASK 36\t:Ensure tftp server is not enabled\t : completed\n"
zypper --non-interactive remove tftp
####### Ensure rsync service is not enabled ######
echo -e "TASK 37\t:Ensure rsync service is not enabled\t : completed\t find status below\n"
rs=`systemctl is-enabled rsyncd`
if [ $rs = enabled ];then
systemctl disable rsyncd && echo "rsync service has been disabled now"
else
echo "already rsync service is disabled"
fi
###### Ensure xinetd is not enabled ############
echo -e "TASK 38\t:Ensure xinetd is not enabled\t : completed\t find status below\n"
xd=`systemctl is-enabled xinetd`
if [ $xd = enabled ];then
systemctl disable xinetd && echo "xinetd service has been disabled now"
else
echo "already xinetd service is disabled"
fi

##### Ensure Avahi Server is not enabled #######
echo -e "TASK 39\t:Ensure Avahi Server is not enabled\t : completed\t find status below\n"
ah=`rpm -qa | grep "^avahi" |wc -l`
if [ $ah -ge 1 ];then
zypper --non-interactive remove avahi && echo "Avahi package has been removed now"
else
echo " Avahi is not installed"
fi
###### Ensure DHCP Server is not enabled ######
echo -e "TASK 40\t:Ensure DHCP Server is not enabled\t : completed\n"
systemctl disable dhcpd
echo "DHCP server has been disabled now"
##### Ensure LDAP server is not enabled #######
echo -e "TASK 41\t:Ensure LDAP server is not enabled\t : completed\n"
systemctl disable slapd 
echo "LDAP server has been disabled now"

##### Ensure DNS Server is not enabled #######
echo -e "TASK 42\t:Ensure DNS Server is not enabled\t : completed\n"
systemctl disable named
echo "DNS server has been disabled now"
##### Ensure HTTP server is not enabled #######
echo -e "TASK 43\t:Ensure HTTP server is not enabled\t : completed\n"
systemctl disable httpd
echo "HTTP server has been disabled now"
##### Ensure IMAP and POP3 server is not enabled ######
echo -e "TASK 44\t:Ensure IMAP and POP3 server is not enabled\t : completed\n"
systemctl disable dovecot
echo "IMAP and POP3 server is disabled now"
##### Ensure Samba is not enabled ########
echo -e "TASK 45\t:Ensure Samba is not enabled\t : completed\n"
systemctl disable smb
echo "Samba is disabled now"
##### Ensure HTTP Proxy Server is not enabled ######
echo -e "TASK 46\t:Ensure HTTP Proxy Server is not enabled\t : completed\n"
systemctl disable squid
echo "Http proxy(SQUID) has been disabled now"
##### Ensure SNMP Server is not enabled #######
echo -e "TASK 47\t:Ensure SNMP Server is not enabled\t : completed\n"
systemctl disable snmpd
echo "SNMP server is disabled now"
##### Ensure NIS Server is not enabled #######
echo -e "TASK 48\t:Ensure NIS Server is not enabled\t : completed\n"
systemctl disable ypserv
echo "NIS server is disabled"

###### Ensure rsyslog Service is enabled #######
echo -e "TASK 49\t:Ensure rsyslog Service is enabled\t : completed\n"
systemctl enable rsyslog
echo "Rsyslog service has been enabled"

##### Ensure NIS Client is not installed #####
echo -e "TASK 50\t:Ensure NIS Client is not installed\t : completed\t find status below\n"
yb=`rpm -qa | grep "^ypbind" |wc -l`
if [ $yb -ge 1 ];then
zypper --non-interactive remove ypbind && echo "NIS Client package has been removed now"
else
echo " NIS client is not installed"
fi
###### Ensure rsh client is not installed ######
echo -e "TASK 51\t:Ensure rsh client is not installed\t : completed\t find status below\n"
rh=`rpm -qa | grep "^rsh" |wc -l`
if [ $rh -ge 1 ];then
zypper --non-interactive remove rsh && echo "RSH package has been removed now"
else
echo " RSH is not installed"
fi
##### Ensure telnet client is not installed #####
echo -e "TASK 52\t:Ensure telnet client is not installed\t : completed\t find status below\n"
tn=`rpm -qa | grep "^telnet" |wc -l`
if [ $tn -ge 1 ];then
zypper --non-interactive remove telnet && echo "telnet package has been removed now"
else
echo " telnet is not installed"
fi
##### Ensure LDAP client is not installed #######
echo -e "TASK 53\t:Ensure LDAP client is not installed\t : completed\t find status below\n"
lc=`rpm -qa | grep "^openldap-clients" |wc -l`
if [ $lc -ge 1 ];then
zypper --non-interactive remove openldap-clients  && echo "LDAP client has been removed now"
else
echo " LDAP client is not installed"
fi

##### Ensure IP forwarding is disabled #######
echo -e "TASK 54\t:Ensure IP forwarding is disabled\t : completed\t find status below\n"
ipfo=`grep  "^net.ipv4.ip_forward" /etc/sysctl.conf | awk -F= '{print $2}'`
if [ $ipfo = 1 ];then
sed -i "s/net.ipv4.ip_forward/#net.ipv4.ip_forward/g" /etc/sysctl.conf 
sed -i "/#net.ipv4.ip_forward/a net.ipv4.ip_forward = 0"  /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=0
echo "IP Forwarding has been disabled"
else
echo " IP Forwarding already disabled"
fi

###### Ensure bootloader password is set ###############
echo -e "TASK 55\t:Ensure bootloader password is set\t : completed\t find status below\n"
( echo test
echo test
)| grub2-mkpasswd-pbkdf2 > /tmp/gp
gp=`cat /tmp/gp | grep "password is" | awk '{print $7}'`
echo "set superusers="root"" >> /etc/grub.d/40_custom
echo "password_pbkdf2 root $gp" >> /etc/grub.d/40_custom
grub2-mkconfig -o /boot/grub2/grub.cfg

####### Ensure authentication required for single user mode #########
echo -e "TASK 56\t:Ensure authentication required for single user mode\t : completed\t find status below\n"
sp=`grep "^ExecStart=" /usr/lib/systemd/system/rescue.service | grep sulogin |wc -l`
if [ $sp = 1 ];then
echo "Already authentication is enabled for single user mode"
else
sed -i "s/ExecStart=/#ExecStart=/g" /usr/lib/systemd/system/rescue.service
sed -i "/#ExecStart=/a ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --job-mode=falil --no-block default"" /usr/lib/systemd/system/rescue.service
echo "Now Authentication is enabled for single user mode"
fi
nts=`systemctl status ntpd | grep Active |awk '{print $2}'`
nts1=`grep "^server" /etc/ntp.conf |wc -l`
cp -r /etc/ntp.conf /bkp/ntp.conf-$d-$h.bkp
if [ $nts = inactive -a $nts1 = 0 ];then
echo "server 10.9.64.4 prefer" >> /etc/ntp.conf
echo "server 10.9.64.5" >> /etc/ntp.conf
service ntpd start && systemctl enable ntpd
echo " Task 57\t: NTP configuration\t:completed"
elif [ $nts = active -a $nts1 -ge 1 ];then
cp -r /etc/ntp.conf /bkp/ntp.conf-$d-$h.bkp
sed -i "s/^server/#server/g" /etc/ntp.conf
echo "server 10.9.64.4 prefer" >> /etc/ntp.conf
echo "server 10.9.64.5" >> /etc/ntp.conf
service ntpd restart && systemctl enable ntpd
echo " Task 57\t: NTP configuration\t:completed"
fi
elif [ $opt = ROLLBACK ];then
cp -r /bkp/login.defs-$d-$h.bkp /etc/login.defs
cp -r /bkp/fstab-$d-$h.bkp /etc/fstab
cp /bkp/sshd_config-$d-$h.bkp /etc/ssh/sshd_config
systemctl reload sshd
cp -r /bkp/useradd-$d-$h.bkp /etc/default/useradd
cp -r /bkp/chargen-$d-$h.bkp /etc/xinetd.d/chargen
cp -r /bkp/daytime-$d-$h.bkp /etc/xinetd.d/daytime
cp -r /bkp/discard-$d-$h.bkp /etc/xinetd.d/discard
cp -r /bkp/echo-$d-$h.bkp /etc/xinetd.d/echo
cp -r /bkp/ntp.conf-$d-$h.bkp /etc/ntp.conf
echo "Successfully rolled out"
elif [ $opt = Quit ]; then
exit
fi
done