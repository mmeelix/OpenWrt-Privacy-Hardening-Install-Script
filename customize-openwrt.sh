#!/bin/sh
#====================================================================
#===  Purpose:	Customize Vanilla Openwrt installation
#===  Created:  MM 2023-07-27
#===  Release:	MM 2023-08-17
#===  License:	MIT
#===
#===  For customisation contact https://github.com/mmeelix or
#===  codemaster@meelix.com
#===
#===  Disclaimer - This scripts is offered “as-is”, without warranty,
#===  and disclaiming liability for damages resulting from the use.
#====================================================================
PUBLIC_DNS_IPS='84.200.70.40 9.9.9.9'

#=== Sanity checks ----------------------------------------
DISTRO="$( ubus call system board | jsonfilter -e '@.release.distribution' )"
if [ -z "${DISTRO}" -o "${DISTRO}" != 'OpenWrt' ]; then
	echo 'Abort: This script will only work with OpenWrt'
	exit 9
fi
VERSION="$( ubus call system board | jsonfilter -e '@.release.version' )"
if [ -z "${VERSION}" -o "${VERSION%%.*}" != '23' ]; then
	echo 'Abort: This script has only been checked for release 23'
	echo 'Disable this check if you want to proceed into unchartered waters.'
	exit 1
fi

#=== Check if system is virgin ----------------------------
if [ $(find /etc -type f -newer /etc/dropbear/dropbear_rsa_host_key | wc -l) -lt 5 ]; then
	IS_VIRGIN=1
else
	IS_VIRGIN=0
fi

echo -e '\n  Run this script only on a freshly imaged file on a sd-card.'
echo    '  The script has been fully tested on my systems but not yours.'
echo    '  So issues might come up that might corrupt your installation and'
echo -e '  that require you to reflash your sd-card.\n'
if [ ${IS_VIRGIN} -eq 1 ]; then
echo    '  Tip: Use the following commands after flashing the image to '
echo    '  stretch the root parition to maximum (free) space available.'
echo    '      RESTORE_DISK=/dev/sdb   #Change sdb where needed'
echo    '      parted -s ${RESTORE_DISK} resizepart 2 100%'
echo    '      sleep 4'
echo    '      resize2fs ${RESTORE_DISK}2'
echo -e '      e2fsck -y -f ${RESTORE_DISK}2\n'
fi
echo    '  If you understand the implications, press Enter to continue'
echo -e '  Or press Ctrl-C now to opt-out.\n'
read -p 'Press Enter to start ' ASK



#=== Some handy functions ---------------------------------
Separator() {
	echo -e '\n\e[33;1m --- \e[0m'
}

Check_IPv4_Valid() {
	if ! echo "$1" | awk  -F'.' 'NF == 4 && $1 <= 255 && $2 <= 255 && $3 <= 255 && $4 != "" && $4 <= 255 {exit 0} {exit 1}'; then
		return 1
	fi
}

Ping_Validation() {
	echo -n "...Ping check for $1: "
	ping -c 1 -W 1 $1 > /dev/null 2>&1
	if [ $? -eq 0 ]; then echo 'Taken/Up'; return 0
	else echo 'Free/Down'; return 1
	fi
}

Check_Internet_Connectivity() {
	#=== Check if we have access to the Internet ------
	Separator
	ROUTE2INET=0
	echo 'Checking Connectivity to the Internet...'
	for ONE in 8.8.8.8 ${PUBLIC_DNS_IPS}; do
		#=== Do some ping checks ------------------
		ping -c 2 -W 1  ${ONE}
		if [ $? -eq 0 ]; then ROUTE2INET=1; break; fi
		echo
	done
	echo
	#=== Also check our resolver ----------------------
	if ! nslookup google.com > /dev/null 2>&1; then ROUTE2INET=0; fi
	if ! nslookup openwrt.org > /dev/null 2>&1; then ROUTE2INET=0; fi
	#=== Abort if needed ------------------------------
	if [ ${ROUTE2INET} -eq 0 ]; then return 1; fi
}

Check_Password_Set() {
	local USERN="$1"
	if [ -z "${USERN}" ]; then return; fi

	#=== Lookup in Shadow -----------------------------
	if grep -q "^${USERN}:" /etc/shadow; then
	    PW_VALUE=$(grep "^${USERN}:" /etc/shadow | cut -d ':' -f 2)
	    if [ -z "${PW_VALUE}" -o "${PW_VALUE}" == '!' -o "${PW_VALUE}" = "*" ]; then
	        #echo "Password is not set for user ${USERN}."
		return 1
	    fi
	else
		echo "Abort: '${USERN}' not found."
		exit 9
	fi
}

Set_UserPassword() {
	local USERN="${1// /}"
	if [ -z "${USERN}" ]; then return; fi

	local ROOTPWD ROOTPWD2
	#=== Keep going until correctly set or skipped ----
	while [ -z "${ROOTPWD2}" ]; do
		#=== Keep trying in case of illegal chars--
		while [ -z "${ROOTPWD}" ]; do
			read -p 'Press Enter to skip or provide your password here: ' ROOTPWD
			if [ -z "${ROOTPWD}" ]; then
				break 2
			else
				#=== Scrub check password--
				if [ "${ROOTPWD}" != "$(echo -n "${ROOTPWD}" | strings)" ]; then
					echo 'Password rejected: Illegal characters'
					ROOTPWD=''
				fi
			fi
		done

		#=== Lets retry again ---------------------
		if [ -n "${ROOTPWD}" ]; then
			read -p 'Enter your password again: ' ROOTPWD2
			if [ -z "${ROOTPWD2}" ]; then
				break
			else
				if [ "${ROOTPWD}" != "${ROOTPWD2}" ]; then
					ROOTPWD2=''; ROOTPWD=''
				else
					echo "Commiting ${USERN}:password to /etc/passwd"
					#==== Set password --------
					echo -e "${ROOTPWD}\n${ROOTPWD2}\n" | passwd root
					#=== Check result code ----
					if [ $? -ne 0 ]; then
						echo 'Password not excepted. Going for the retry.'
						ROOTPWD2=''; ROOTPWD=''
					fi
				fi
			fi
		fi
	done
}

#=== Sets better prompt for users that have many open ssh connections ---
Set_Better_Prompt() {
	local TAG="$1"
	sed -i '/^export PS1=/s/.*/export PS1="\\[\\e[33;1m\\]\\u@\\h-'${TAG}':\\w\\$ \\e[0m"/' /etc/profile
}

#=== Set LAN IP -------------------------------------------
Set_Network_IPs() {
	#=== Feedback -------------------------------------
	Separator
	echo -n 'Your Current LAN IPv4: '; uci get network.lan.ipaddr
	if [ "$(uci get network.wan.proto)" == 'dhcp' ]; then
		echo 'Your Current WAN IPv4: DHCP'
	else
		echo -n 'Your Current WAN IPv4: '; uci get network.wan.ipaddr
		echo -n 'Your Current  GW IPv4: '; uci get network.wan.gateway
	fi

	#=== Ask for LAN IPv4 -----------------------------
	while [ -z "${LANIP}" ]; do
		echo; read -p 'Enter IPv4 address for LAN (press Enter to skip): ' LANIP
		#=== Return if no address supplied --------
		if [ -z "${LANIP}" ]; then return; fi
		#=== Check if address is valid ------------
		if ! Check_IPv4_Valid "${LANIP}"; then LANIP=''; fi
		#=== Check if address is taken ------------
		if [ "${LANIP}" != $(uci get network.lan.ipaddr) ] && Ping_Validation "${LANIP}"; then LANIP=''; fi
	done

	#=== Ask fo WAN IPv4 -----------------------------
	while [ -z "${WANIP}" ]; do
		read -p 'Enter IPv4 address for WAN (DHCP is valid): ' WANIP
		#=== Return Exit is no address supplied ----------
		if [ -z "${WANIP}" ]; then return; fi
		#=== Check if address is valid ------------
		case "${WANIP}" in
			[dD][hH][cC][pP]) WANIP='dhcp';;
			*)		  if ! Check_IPv4_Valid "${WANIP}"; then WANIP=''; fi
		esac
	done

	if [ "${WANIP}" == 'dhcp' ]; then
		uci set network.wan.proto='dhcp'
		#=== Clear these if coming from Static ----
		uci delete network.wan.ipaddr 2>/dev/null
		uci delete network.wan.netmask 2>/dev/null
		uci delete network.wan.gateway 2>/dev/null
	else
		#=== Set to static address ---------------
		#=== Ask for gateway ---------------------
		while [ -z "${GWIP}" ]; do
			read -p 'Enter IPv4 address for Internet Gateway: ' GWIP
			#=== Exit is no address supplied --
			if [ -z "${GWIP}" ]; then return; fi
			#=== Check if address is valid ----
			if ! Check_IPv4_Valid "${GWIP}"; then GWIP=''; fi
			if [ "${GWIP}" == "${WANIP}" ]; then GWIP=''; fi
		done
		#=== Now set to OS ------------------------
		uci set network.wan.proto='static'
		uci set network.wan.ipaddr="${WANIP}"
		uci set network.wan.netmask='255.255.255.0' #=- This one is presumed
		uci set network.wan.gateway="${GWIP}"
	fi

	#=== Set given IPv4 to LAN ------------------------
	uci set network.lan.ipaddr="${LANIP}"
	#=== Also set better prompt -----------------------
	Set_Better_Prompt "${LANIP}"

	#=== Just to make sure ----------------------------
	uci set network.wan.disabled='0'
	#=== Set temp bootsrap public DNS server ----------
	uci set network.wan.dns="${PUBLIC_DNS_IPS}"

	#=== IPv6 is mostly overlooked by sys admins. It has become
	#=== a path for leaks for big tech ----------------
	#=== Lets try to close this -----------------------
	echo -e '\n...Heads-up *** IPv6 will be disabled next....'
	uci set network.wan6.proto='none'
	uci set network.lan.ip6assign='0'
	uci set network.@interface[0].ip6assign='0'

	#=== Tell user -----------------------------------
	echo -e "\n  Next step: Change network settings. Make sure you will have access to ${LANIP}"
	echo -e '  Login with ssh on new IP and run this script again to continue\n'
	read -p 'Ctrl-C now or press Enter to commit the network changes. ' WAIT

	#=== Go! Lets commit ------------------------------
	uci commit network
	/etc/init.d/network restart &
	exit 0
}


#==========================================================
#===  Ask for network settings
#===-------------------------------------------------------
if [ "$(uci get network.lan.ipaddr)" == '192.168.1.1' -o ${IS_VIRGIN} -eq 1 ]; then
	Set_Network_IPs
fi


#==========================================================
#===  Set some system settings
#===-------------------------------------------------------

LANIP="$(uci get network.lan.ipaddr)"
#=== Create a more differentiating prompt -----------------
if [ $(grep -c "^export PS1=.*${LANIP}:" /etc/profile) -eq 0 ]; then
	Set_Better_Prompt "${LANIP}"
fi

#=== For bigger root partition add var_persistent (hold over boots) ---
VAR_PERSIST='/var_persistent'
if [ ! -d ${VAR_PERSIST} -a $( df -m | awk '{if ($6=="/") {print $2;exit}}' ) -gt 500 ]; then
	#=== /var is still symlink to tmp, remove ----------
	if [ ! -d ${VAR_PERSIST} ]; then mkdir ${VAR_PERSIST}; fi
fi

#=== Ensure that we use/redirect to HTTPS always ----------
#=== Exploit in eg. Browser can connect to this http ------
uci set uhttpd.main.redirect_https='1'
uci commit uhttpd
service uhttpd restart

#=== Disable UPnP (always) --------------------------------
#....

#=== On boot the DNS might not be running (because time is not set yet).
#=== So add an IP to the ntp server list to bootstrap
#=== 162.159.200.123 = time.cloudflare.com ----------------
NTP_IP='162.159.200.123'
if [ $(uci get system.ntp.server | grep -c ${NTP_IP}) -eq 0 ]; then
	#=== Add IP to beginning of list -------
	uci set system.ntp.server="${NTP_IP} $( uci get system.ntp.server )"
	uci commit system
	/etc/init.d/sysntpd restart
fi

#=== Check if root password has already been set ----------
USR_ROOT='root'
if ! Check_Password_Set ${USR_ROOT}; then
	Separator
	echo    " '${USR_ROOT}' password not set. Enter it here or with the Luci Web Interface."
	echo -e '  Note: Yes it is insecure, just like you are logged in the 1st time without any password\n'
	Set_UserPassword root
fi

#=== Disable password logon through ssh --------------------
SSH_AUTH_KEYS='/etc/dropbear/authorized_keys'
if [ ! -f ${SSH_AUTH_KEYS} ]; then
	Separator
	echo    "  Upload your 'authorized_keys' file now for ssh login."
	echo -e '  Place authorized_keys file in same directory as this script\n'
	read -p 'Press Enter when done/skip to continue ' WAIT
	if [ -f ./authorized_keys ]; then
		echo "...Copying authorized_keys to ${SSH_AUTH_KEYS}..."
		cp ./authorized_keys ${SSH_AUTH_KEYS}
		if [ $? -eq 0 ]; then
			echo '...Password logon will now be disabled...'
			uci set dropbear.@dropbear[0].PasswordAuth='off'
			uci set dropbear.@dropbear[0].RootPasswordAuth='off'
			echo '...Restricting SSH access to LAN only...'
			uci set dropbear.@dropbear[0].GatewayPorts='off'

		fi
		#=== Pick up changes ----------------------
		/etc/init.d/dropbear restart
	fi
fi



#==========================================================
#===  Install some extra software and configure
#===-------------------------------------------------------

#=== We need access to Internet to continue ----------------
if ! Check_Internet_Connectivity; then 	echo 'Abort: We need a working connection to Internet to continue'; exit 1; fi

#=== Download available packages if needed ----------------
if [ ! -d ${VAR_PERSIST}/opkg-lists/ ]; then mkdir ${VAR_PERSIST}/opkg-lists/; fi
if [ -z "$( find ${VAR_PERSIST}/opkg-lists/ -type f -mindepth 1 -maxdepth 1 2> /dev/null )" ]; then
	sed -i 's|/var\/opkg-lists|'${VAR_PERSIST}'/opkg-lists|' /etc/opkg.conf
	if ! opkg update; then
		echo '  Oops: Cant retrieve packages from Openwrt. Need to abort this this script'
		echo '  Check your internet and try again'
		exit 1
	fi
fi

#=== vnstat to stop unexpected of volumes of traffic ------
#=== database can grow, so only install on BIG_PART -------
while [ -d ${VAR_PERSIST} -a -z "$(opkg list-installed | grep '^vnstat2 ' )" ]; do
	Separator
	echo '...Installing vnstat2...'

	#=== Install package ------------------------------
	if ! opkg install vnstat2 luci-app-vnstat2; then break; fi

	#=== Set configuration -----------------------------
	#=== Bug on commiting this, so do work around ------
	#uci set vnstat.@vnstat[0].interface='br-lan eth0'
	#=== bug, so this workaround -----------------------
	#=== Also weird config behaviour -------------------
	echo '' > /etc/config/vnstat
	echo 'config vnstat' >> /etc/config/vnstat
	echo "        list interface 'br-lan'" >> /etc/config/vnstat
	echo "        list interface '$(uci get network.wan.device)'" >> /etc/config/vnstat
	echo '' >> /etc/config/vnstat

	#=== Move db to var_persistent ---------------------
	DB_LOC="${VAR_PERSIST}/lib/vnstat"
	if [ ! -d ${DB_LOC} ]; then mkdir -p ${DB_LOC}; fi
	echo 'DatabaseDir "'${DB_LOC}'"' >> /etc/vnstat.conf

	#=== commit -------------------------------
	uci commit vnstat
	service vnstat enable
	service vnstat restart
	break
done

#=== BCP38 This is less about protecting your router and more about preventing
#=== your network's contribution to some types of DoS/DDoS attack. Also see:
#=== http://www.bcp38.info/index.php/Main_Page

#=== Check if Installed -----------------------------------
while ! uci -q show bcp38 > /dev/null 2>&1 || [ -z "$(opkg list-installed | grep '^bcp38 ' )" ]; do
	Separator
	echo '...Installing BCP38...'

	#=== Install packages -----------------------------
	if ! opkg install bcp38 luci-app-bcp38; then break; fi

	#=== Set configuration --------------------
	uci set bcp38.@bcp38[0].enabled='1'
	#=== Adjust to match your WAN port - may be something like eth0.2 for example.
	uci set bcp38.@bcp38[0].interface="$(uci get network.wan.device)"

	#=== commit -------------------------------
	uci commit bcp38
	service bcp38 enable
	service bcp38 restart
	break
done

#=== Remove DNSMasq and install dnscrypt-proxy2 for better privacy ---
DNSCRYPT_CFG='/etc/dnscrypt-proxy2/dnscrypt-proxy.toml'
while [ $( opkg list-installed | grep -c '^dnscrypt-proxy2 ' ) -eq 0 ]; do
	Separator
	echo '...Removing DNSMasq, Installing DNSCrypt-Proxy...'

	#=== Install dnscrypt-proxy2 ----------------------
	if ! opkg install dnscrypt-proxy2; then break; fi

	#=== Remove  dnsmasq: No need for DHCP and DNS through dnscrypt-proxy2
	if [ -f /etc/init.d/dnsmasq ]; then
		/etc/init.d/dnsmasq stop
		opkg remove dnsmasq
	fi
	#=== Clear these values ---------------------------
	uci set ucitrack.@dhcp[0].init=''
	uci delete dhcp.@dnsmasq[0] > /dev/null 2>&1
	uci commit dhcp

	#=== Update config --------
	LANIP="$(uci get network.lan.ipaddr)"
	sed -i 's/^listen_addresses.*$/listen_addresses = \[\'"'"'127.0.0.53:53'"'"', '"'"${LANIP}':53'"'"'\]/' ${DNSCRYPT_CFG}

	#=== Set DNS to our own ---------------------------
	uci set network.wan.peerdns='0'
	#=== double down: Set static resolver -------------
	uci set network.wan.dns='127.0.0.53'
	uci set network.wan.resolvfile='/etc/resolv.conf'
	#=== tripple down: Set static for lan -------------
	uci set network.lan.dns="${LANIP}"
	uci set network.lan.resolvfile='/etc/resolv.conf'
	uci commit network

	#=== Note: many service update /etc/resolv.conf, like netifd, upstream dhcp
	#=== Flush current /etc/resolv.conf ---------------
	echo '# Interface wan' > /etc/resolv.conf
	echo 'nameserver 127.0.0.53' >> /etc/resolv.conf

	#=== Start service --------------------------------
	/etc/init.d/dnscrypt-proxy restart

	#=== Check the result -----------------------------
	sleep 2
	Separator; echo '...Checking if DNS is running...'
	ps -w | grep '[d]ns'
	Separator; echo '...Checking the DNS listen ports...'
	netstat -an | grep ':53'
	#=== Lets check how it all gets resolved. Test with github.com
	Separator; echo '...Trying to resolve: openwrt.org, github.com or google.com...'
	sleep 2
	for TRY in openwrt.org github.com google.com; do
		if dnscrypt-proxy -config ${DNSCRYPT_CFG} -resolve ${TRY}; then break; fi
		sleep 4
	done
	echo; read -p 'Press ENTER to Continue ' WAIT
	break
done


#=== Create an extra hurdle for the unwanted --------------
while [ $( opkg list-installed | grep -c '^banip ' ) -eq 0 ]; do
	Separator
	echo '...Installing BanIP...'

	#== Install banip ---------------------------------
	if ! opkg install banip luci-app-banip; then break; fi

	#=== Set configuration ----------------------------
	uci set banip.global.ban_enabled='1'
	uci set banip.global.ban_dev="$(uci get network.wan.device)"
	uci set banip.global.ban_deduplicate='1'
	uci set banip.global.ban_autoblocklist='1'
	uci set banip.global.ban_autoblocksubnet='1'
	uci set banip.global.ban_nftexpiry='1m'
	uci set banip.global.ban_cores='2'
	uci set banip.global.ban_loglimit='250'

	#=== Set Sources ----------------------------------
	#=== Also see https://github.com/openwrt/packages/blob/master/net/banip/files/README.md
	uci set banip.global.ban_feed='backscatterer bruteforceblock cinsscore debl etcompromised firehol1 firehol2 greensnow proxy voip'

	#=== Commit to live system ------------------------
	uci commit banip
	service banip enable
	service banip restart
	service uhttpd restart
	break

done

#=== Offer to install Tor as an transparent proxy ---------
while [ $( opkg list-installed | grep -c '^tor ') -eq 0 ]; do

	Separator
	echo '  Tor can be installed as an Transparent Proxy. Please read the included readme file.'
	echo '  Tip: Install the Tor Transparent Proxy on a separate device behind your main router.'
	echo -e '\n  WARNING: Transparent Proxying Tor will NOT give you anonymity, without creating an'
	echo -e '  isolating proxy on your Desktop. It just wont. It s*cks, I know.\n'
	read -p 'Install & Configure Tor as a transparent Proxy? (y/N) ' ANSWER
	case "${ANSWER}" in
		Y|y)	echo -e '\n...Installing Tor as a Transparent Proxy...';;
		*)	break;;
	esac

	#=== Install Tor ----------------------------------
	if ! opkg install tor tor-geoip; then
		echo 'Abort: Error Installing Tor and/or dependancies'
		break
	fi

	#=== Set configuration of torrc -------------------
	TOR_DATADIR='/var_persistent/lib/tor'
	if [ ! -d ${TOR_DATADIR} ]; then
		mkdir ${TOR_DATADIR}
		chown tor:tor ${TOR_DATADIR}
		chmod 700 ${TOR_DATADIR}
		cp -pR /var/lib/tor/* ${TOR_DATADIR}/
	fi
	sed -i 's|^DataDirectory /var/lib/tor|DataDirectory '${TOR_DATADIR}'|' /etc/tor/torrc

	#=== \EOF Literal - EOF insert variables ----------
	cat <<EOF >> /etc/tor/torrc &&
SOCKSPort 9050
SOCKSPort ${LANIP}:9050
SOCKSPolicy accept ${LANIP%.*}.0/24
SOCKSPolicy reject *

TransPort ${LANIP}:9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort

DNSPort 9053
DNSPort ${LANIP}:9053
AutomapHostsOnResolve 1

GeoIPFile /usr/share/tor/geoip
GeoIPv6File /usr/share/tor/geoip6

#=== Tweaks ---
CircuitBuildTimeout 5
KeepalivePeriod 60
NewCircuitPeriod 12
NumEntryGuards 8

ExcludeNodes {us},{hk},{uk},{sg},{au}
ExcludeExitNodes {us},{hk},{uk},{nl},{au}
#ExitNodes {is}

EOF

	#=== Restart with new settings --------------------
	service tor restart

	#=== Check ----------------------------------------
	ps -w | grep /sbin/[t]or
	netstat -an | grep ':90'

	#=== Also route dnscrypt-proxy over tor -----------
	sed -i 's/^.*force_tcp = false/force_tcp = true/' ${DNSCRYPT_CFG}
	sed -i 's|^.*proxy = '"'"'socks5:.*$|proxy = '"'"'socks5://'${LANIP}':9050'"'"'|' ${DNSCRYPT_CFG}
	#=== Restart --------------------------------------
	/etc/init.d/dnscrypt-proxy restart

	#=== Now lets add the transparent proxy firewall rules ----
	for RULE in CatchDNS:53 Catch22:22 Catch80:80 Catch443:443 Catch9050:9050 Catch9040:9040; do
		FWID="$(uci add firewall redirect)"
		uci set firewall.${FWID}.name="${RULE%:*}"
		uci set firewall.${FWID}.target='DNAT'
		uci set firewall.${FWID}.src='lan'
		uci set firewall.${FWID}.src_dport="${RULE#*:}"
		uci set firewall.${FWID}.src_dip="${LANIP}"
		uci set firewall.${FWID}.dest='lan'
		uci set firewall.${FWID}.dest_ip="${LANIP}"
		uci set firewall.${FWID}.dest_port="${RULE#*:}"
	done

	#=== Catch All, Redirect All ----------------------
	FWID="$(uci add firewall redirect)"
	uci set firewall.${FWID}.name='Redirect-LAN-2Tor9040'
	uci set firewall.${FWID}.target='DNAT'
	uci set firewall.${FWID}.src='lan'
	uci set firewall.${FWID}.src_dport='1-65535'
	uci set firewall.${FWID}.dest='lan'
	uci set firewall.${FWID}.dest_ip="${LANIP}"
	uci set firewall.${FWID}.dest_port='9040'

	#=== Reject Other ---------------------------------
	FWID="$(uci add firewall rule)"
	uci set firewall.${FWID}.name='Drop-Other-Protos'
	uci add_list firewall.${FWID}.proto='icmp'
	uci add_list firewall.${FWID}.proto='igmp'
	uci add_list firewall.${FWID}.proto='esp'
	uci set firewall.${FWID}.src='lan'
	uci set firewall.${FWID}.dest='wan'
	uci set firewall.${FWID}.target='REJECT'

	#=== disable --------------------------------------
	for RULE in IPSec-ESP ISAKMP; do
		NUMB=$(uci show firewall | grep ${RULE} | awk -F '.name' '{print $1}' )
		uci set ${NUMB}.enabled='0'
	done

	#=== Commit and enable -----------------------------
	uci set firewall.@defaults[0].drop_invalid='1'
	uci commit firewall
	service firewall restart
	break
done

echo -e '\n\n'
echo '  Congratulations! The Openwrt Privacy Hardening has been completed succesfully!'
echo '  Remember: Default functionality has been disable to improve your privacy protection'
echo -e '  Eg: DHCP=disabled, IPv6=disabled, Ping=disabled with Tor.\n'
echo '  Consider: Mullvad Browser, Linux, Isolationing Deskop Proxy, https://privacytests.org/'
echo -e '  https://ipv6leak.com/  https://dnsleaktest.com/  https://panopticlick.eff.org\n\n'
read -p 'Press Enter to reboot Openwrt ' ASK


exit 0
#===[EOF]===
