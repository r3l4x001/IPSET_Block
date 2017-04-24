#!/bin/sh
VER="v3.04"
#======================================================================================================= © 2016-2017 Martineau, v3.04
#
# Dynamically block unsolicited access attempts using IPSETs. Useful if you have opened ports >1024 as hopefully hackers will
#             start their attempts at the more common ports e.g. 22,23 etc. so will be banned BEFORE they reach your port!
#             NOTE: For ARM routers (IPSET v6.3) Blacklist entries are retained for 7 days unless arg HH:MM:SS is specified/hard-coded)
#
#     IPSET_Block   [help | -h] | [status [list]] [reset] [delete] [ban {'ip_addr'}] [unban {'ip_addr'}] [restore] [nolog]
#                               { init [reset] ['hh:mm:ss'] [method1] }
#
#     IPSET_Block   
#                   Displays the number of currently banned I/Ps and the number of banned IPs added since the last status request:
#                       e.g. '	Summary Blacklist: 12882 IPs currently banned - 4 added since: Apr 16 15:27 (Entries auto-expire after 24:00:00)'
#     IPSET_Block   status list
#                   Display the contents of IPSETs Whitelist & Blacklist - beware there could be a lot!!!
#     IPSET_Block   reset
#                   Temporarily flush the IPSET Blacklist (It will be restored @BOOT or manually using the restore cmd)
#     IPSET_Block   restore
#                   Restore the IPSETs Whitelist & Blacklist from the current saved IPSETs.
#                   (If 'delete' was used then you need to clone the 'backup' file before attempting the restore!)
#     IPSET_Block   ban 12.34.56.7
#                   Adds 12.34.56.7 to IPSET Blacklist
#     IPSET_Block   unban 12.34.56.7
#                   Removes 12.34.56.7 from IPSET Blacklist
#     IPSET_Block   delete
#                   Permanently flush the IPSET Blacklist (It cannot be restored @BOOT or using the restore cmd)
#     IPSET_Block   init
#                   If 'IPSET_Block.config' exists it will be used to restore IPSETs Blacklist and Whitelist,
#                      otherwise the IPSETs are created empty - same as if 'init reset' was specified to override the auto-restore
#     IPSET_Block   init reset 12:34:56 nolog
#                   Empty IPSETs will be created with any added Blacklist entries auto-expiring after 12 hrs 34 mins and 56 secs!
#                         (default expiry time is 168:00:00 = 7 Days)
#                          NOTE: No 'Block =' messages will be generated.
#
# /jffs/scripts/init-start
#      /usr/sbin/cru a IPSET_SAVE   "0 * * * * /jffs/scripts/IPSET_Block.sh save"    #Every hour
#      /usr/sbin/cru a IPSET_BACKUP "0 5 * * * /jffs/scripts/IPSET_Block.sh backup"  #05:00 every day
#
# /jffs/scripts/firewall-start
#      /jffs/scripts/IPSET_Block.sh init nolog
#
# NOTE: Whitelist will be automatically populated with local LAN subnet, but VLANs will need to be added manually e.g. 10.0.0.0/8 etc.
#
# Credit @adamm https://www.snbforums.com/threads/how-to-dynamically-ban-malicious-ips-using-ipset-firewall-addition.16798/#post-115872
# Also Very good examples of using IPSETs for blocking dynamically! https://forums.gentoo.org/viewtopic-t-863121.html

# Print between line beginning with '#==' to first blank line inclusive
ShowHelp() {
	awk '/^#==/{f=1} f{print; if (!NF) exit}' $0
}

Delete_IPSETs () {
	iptables -D INPUT -m set $MATCH_SET Whitelist src -j ACCEPT 2> /dev/null > /dev/null
	iptables -D INPUT -m set $MATCH_SET Blacklist src -j DROP 2> /dev/null > /dev/null
	iptables -D logdrop -m state --state NEW -j SET --add-set Blacklist src 2> /dev/null > /dev/null
	ipset -q $FLUSH Whitelist
	ipset -q $FLUSH Blacklist
	ipset -q $DESTROY Whitelist
	ipset    $DESTROY Blacklist
	rm $bannedips  2> /dev/null	# Reset counter '0'
}
Convert_HHMMSS_to_SECS () {
	echo $(echo $1 | awk -F':' '{print $1 * 60 * 60 + $2 * 60 + $3}')
}
Convert_SECS_to_HHMMSS() {
	HH=$((${1}/3600))
	MM=$((${1}%3600/60))
	SS=$((${1}%60))
	echo $(printf "%02d:%02d:%02d\n" $HH $MM $SS)
}
Chain_exists() {
	# Args: {Chain_name} [table_name]
    local chain_name="$1" ; shift
    [ $# -eq 1 ] && local table="-t $1"
    iptables $table -n --list $chain_name >/dev/null 2>&1
	local RC=$?
	if [ $RC -eq 1 ];then
		echo "N"
		return 1
	else
		echo "Y"
		return 0
	fi
}

MYROUTER=$(nvram get computer_name)

################################################Customise for local use #############################################
if [ -d  "/tmp/mnt/"$MYROUTER ];then
	DIR="/tmp/mnt/"$MYROUTER				# <== USB Location of IPSET save/restore configuration
else
	DIR="/tmp"								#         NOTE: /TMP isn't permanent! ;-) but allows testing of save/restore
fi

HHMMSS="168:00:00"							# <== Specify retention period to keep Blacklist entries or passed via 'init reset' hh:mm:ss' invocation
											#			e.g. 168 hrs = 7 days
#####################################################################################################################

bannedips=$DIR"/IPSET_Blacklist_Count"		# Allows display of count of new blocked IPs after every implied/ explicit status request

# 380.63+ for ARM routers, IPSET v6  is available...Load appropriate IPSET modules
case $(ipset -v | grep -o "v[4,6]") in
  v6) MATCH_SET='--match-set'; LIST='list'; CREATE='create'; SAVE='save'; RESTORE='restore'; FLUSH='flush'; DESTROY='destroy'; ADD='add'; SWAP='swap'; IPHASH='hash:ip'; NETHASH='hash:net'; SETNOTFOUND='name does not exist'; TIMEOUT='timeout'
      lsmod | grep -q "xt_set" || for module in ip_set ip_set_hash_net ip_set_hash_ip xt_set
	  do modprobe $module; done;;
  v4) MATCH_SET='--set'; LIST='--list'; CREATE='--create'; SAVE='--save'; RESTORE='--restore'; FLUSH='--flush'; DESTROY='--destroy'; ADD='--add'; SWAP='--swap'; IPHASH='iphash'; NETHASH='nethash'; SETNOTFOUND='Unknown set'; TIMEOUT=; RETAIN_SECS=
      lsmod | grep -q "ipt_set" || for module in ip_set ip_set_nethash ip_set_iphash ipt_set
      do modprobe $module; done;;
  *) logger -st "($(basename $0))" $$ "**ERROR** Unknown ipset version: $(ipset -v). Exiting." && (echo -e "\a";exit 99);;
esac


# Need assistance!???
if [ "$1" == "help" ] || [ "$1" == "-h" ]; then
	ShowHelp
	exit 0
fi

logger -st "($(basename $0))" $$ $VER "© 2016-2017 Martineau, Dynamic IPSET Blacklist banning request....."

# Check if logging messages are to be enabled/disabled (Allow it to be processed at any time rather than in the 'init' clause)
NOLOG=0																# Create Syslog "Block =" messages
if [ "$1" != "init" ] && [ $(Chain_exists "Blacklist")  == "Y" ] && \
						  [ $(iptables --line -L Blacklist | grep -c "state NEW LOG") -eq 0 ];then
	NOLOG=1															# Already suppressed, so leave it supressed until next reboot or 'init reset' issued
else
	if [ "$(echo $@ | grep -c 'nolog')" -gt 0 ];then
		NOLOG=1														# Suppress "Block =" messages from Syslog
	fi
fi


# What is the action required?
ACTION=$1


# If the first arg is an I/P address or subnet then assume it is to be blocked.
# TBA


# status / ban / unban / reset / delete / save / ban / whitelist / backup / init

case $ACTION in
	status)
		echo -en "\n"
		ipset -L Blacklist | head -n 7									# Sadly 'ipset -t Blacklist' to list only the IPSET header doesn't work on Asus
		if [ "$2" == "list" ];then										# Verbose if 'status list' 
			ipset -L Blacklist								| \
				grep -E "^[0-9]"							| \
				sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4	| \
				awk ' {printf "%15s\t", $1;}'
			echo -en "\n\n"
			ipset -L Whitelist
		fi
		;;
	ban)
		if [ -z $2 ];then
			echo "Input IP Address"
			read bannedip
		else
			bannedip=$2
		fi
		logger -st "($(basename $0))" $$  "Banning" $bannedip "- added to Blacklist....."
		ipset -q -A Blacklist $bannedip
		echo "$bannedip Is Now Banned"
		;;
	unban)
		if [ -z $2 ]; then
			echo "Input IP Address To Unban"
			read unbannedip
		else
			unbannedip=$2
		fi
		logger -st "($(basename $0))" $$  "Unbanning and removing" $unbannedip "from Blacklist......"
		ipset $DELETE Blacklist $unbannedip
		echo "`sed /$unbannedip/d $DIR/IPSET_Block.config`" > $DIR/IPSET_Block.config
		echo $unbannedip "Is Now Unbanned"

		;;
	reset)
		logger -st "($(basename $0))" $$  "Temporarily Allowing ALL ("$(cat $bannedips)") I/P's in Blacklist IPSET"
		NOW=$(date +"%Y%m%d-%H%M%S")    # current date and time
		mv  $DIR/IPSET_Block.config $DIR/IPSET_Block.config-$NOW			# Create restore backup
		ipset $FLUSH Blacklist
		ipset $SAVE Blacklist >  $DIR/IPSET_Block.config
		ipset $SAVE Whitelist >> $DIR/IPSET_Block.config
		rm $bannedips 2> /dev/null						# Reset counter '0'
		;;
	delete)
		#expr `ipset -L Blacklist | grep -v -E "^[NTRHSM]" | wc -l` > $bannedips
		logger -st "($(basename $0))" $$  "Permanently deleting ALL ("$(cat $bannedips)") I/Ps from Blacklist."
		ipset $FLUSH Blacklist
		ipset $SAVE Blacklist >  $DIR/IPSET_Block.config
		ipset $SAVE Whitelist >> $DIR/IPSET_Block.config
		rm $bannedips 2> /dev/null						# Reset counter '0'
		;;
	save)
		logger -st "($(basename $0))" $$  "Saving IPSET Block rules to "$DIR"/IPSET_Block.config....."
		# Only save the IPSETs associated with this script
		ipset $SAVE Blacklist >  $DIR/IPSET_Block.config
		ipset $SAVE Whitelist >> $DIR/IPSET_Block.config
		;;
	restore)
		logger -st "($(basename $0))" $$  "Restoring IPSET Block rules Whitelist & Blacklist from "$DIR"/IPSET_Block.config....."
		#/jffs/scripts/$(basename $0) "init" &
		# Rather than destroy the IPSETs, keep them live, and simply swap the restore!! 
		if [ ! -z "$(ipset $LIST -n | uniq | grep -oE "^Blacklist")" ];then
			# Need to enforce the restore to temporary '_Blacklist' & '_Whitelist' IPSETs
			cp $DIR/IPSET_Block.config $DIR/IPSET_Block.config.preEDIT					# Save the config
			sed -i 's/Blacklist/_Blacklist/g' $DIR/IPSET_Block.config					# Change the IPSET names in the saved config
			sed -i 's/Whitelist/_Whitelist/g' $DIR/IPSET_Block.config
			ipset -X _Blacklist 2> /dev/null;ipset -X _Whitelist 2> /dev/null			# Make sure the temporary swap IPSETs don't exist
			ipset $RESTORE -f  $DIR/IPSET_Block.config									# Do the restore.....
			if [ $? -eq 0 ];then
				ipset swap _Blacklist Blacklist;ipset swap _Whitelist Whitelist			# Perform the swap
				ipset -X _Blacklist 2> /dev/null;ipset -X _Whitelist 2> /dev/null		# Delete the temporary IPSETs
			else
				echo -e "\aWhoops!!!"
				exit 99
			fi
			rm $DIR/IPSET_Block.config													# Delete the edited temporary config
			mv $DIR/IPSET_Block.config.preEDIT $DIR/IPSET_Block.config					#    and recover the original config
		else
			ipset $RESTORE < $DIR/IPSET_Block.config
		fi
		;;
	whitelist)
		echo "Input file location"						# see /jffs/configs/IPSET_Whitelist
		read WHITELISTFILE
		for IP in `cat $WHITELISTFILE`
			do
				ipset -q -A Whitelist $IP
				echo $IP
			done

		ipset $SAVE Whitelist >  $DIR/IPSET_Block.config
		ipset $SAVE Blacklist >> $DIR/IPSET_Block.config
		;;
	backup)
		logger -st "($(basename $0))" $$  "Creating IPSET rule backup to '"$DIR"/IPSET_Block.configbak'....."
		cp -f $DIR/IPSET_Block.config $DIR/IPSET_Block.configbak
		;;
	init)
		# Usually called from firewall-start, but may be invoked manually at any time from command prompt

		# Optionally track which port is being targeted by the hacker
		BLACKLIST_TYPE=$IPHASH
		if [ "$(echo $@ | grep -c 'port')" -gt 0 ];then				# Port tracking requested?
			BLACKLIST_TYPE='hash:ip,port'
		fi

		# Check if original 'logdrop' chain is to be implemented. i.e. 1-logdrop; 0-Blacklist chain method
		USE_LOGDROP=0													# Use new Martineau non-logdrop custom Blacklist chain method
		if [ "$(echo $@ | grep -c 'method1')" -gt 0 ];then				# Command arg override?
			USE_LOGDROP=1												# Use original 'logdrop' chain method
		fi

		# Calculate Blacklist retention period in seconds (if specified)
		if [ "$1" == "init" ] && [ "$2" == "reset" ] && \
								  [ ! -z $3 ] && [ "$3" != "port" ] && [ "$3" != "nolog" ];then	# Allow 'init reset HH:MM:SS' to specify retain period
			HHMMSS=$3
		fi
		

		RETAIN_SECS=
		if [ ! -z $TIMEOUT ];then
			RETAIN_SECS=$(Convert_HHMMSS_to_SECS "$HHMMSS")
		fi

		if [ $USE_LOGDROP -eq 1 ];then				# Original 'logdrop' chain method?
			if [ "$(nvram get fw_log_x)" == "drop" ] || [ "$(nvram get fw_log_x)" == "both" ];then
				#logger -st "($(basename $0))" $$ "***DEBUG Correct use of 'logdrop' CHAIN Setting Detected"
				DUMMY=
			else
				
				logger -st "($(basename $0))" $$  "Setting 'Firewall logging=DROP' - will use 'logdrop' chain....."
				nvram set fw_log_x=drop
				nvram commit
			fi
		else
			#logger -st "($(basename $0))" $$  "***DEBUG Skipping Setting 'Firewall logging=DROP' - will use 'Blacklist' chain"
			DUMMY=
		fi

		if [ "$(nvram get fw_enable_x)" == "1" ]
		then
			#logger -st "($(basename $0))" $$ "***DEBUG Correct 'Firewall=ENABLED' setting Detected."
			DUMMY=
		else
			logger -st "($(basename $0))" $$ "Setting 'Firewall=ENABLED'....."
			nvram set fw_enable_x=1
			nvram commit
		fi

		# 'init' will restore IPSETs from file but 'init reset' will re-create empty IPSETs even if 'IPSET_Block.config' exists
		if [ "$2" == "reset" ] || [ ! -s "${DIR}/IPSET_Block.config" ];then
			logger -st "($(basename $0))" $$  "IPSETs: 'Blacklist/Whitelist' created EMPTY....." [$1 $2]
			iptables -F Blacklist
			Delete_IPSETs
			ipset -q $CREATE Whitelist $NETHASH
			ipset    $CREATE Blacklist $BLACKLIST_TYPE $TIMEOUT $RETAIN_SECS		# Entries are valid for say 86400 secs i.e. 24 hrs (IPSET v6.x only)
		else
			# Delete the Blacklist firewall rules to allow the Blacklist/Whitelist IPSETs to be deleted/restored (rather than swap!)
			iptables -D INPUT -m set $MATCH_SET Blacklist src -j DROP 2> /dev/null
			iptables -D INPUT -m set $MATCH_SET Whitelist src -j ACCEPT 2> /dev/null
			
			iptables -D INPUT -i $(nvram get wan0_ifname) -m state --state INVALID -j Blacklist  2> /dev/null		# WAN only
			iptables -D INPUT                                -m state --state INVALID -j Blacklist  2> /dev/null		# ALL Interfaces
			iptables -D INPUT -j Blacklist 2> /dev/null
			iptables -D Blacklist -m state --state NEW -j SET --add-set Blacklist src 2> /dev/null
						
			ipset destroy Blacklist  2> /dev/null;ipset destroy Whitelist 2> /dev/null
			logger -st "($(basename $0))" $$  "IPSET restore from '"$DIR"/IPSET_Block.config' starting....."
			ipset $RESTORE  < $DIR/IPSET_Block.config
			XRETAIN_SECS=$(ipset $LIST Blacklist | head -n 4 | grep -E "^Header" | grep -oE "timeout.*" | cut -d" " -f2)
			if [ ! -z XRETAIN_SECS ];then
				RETAIN_SECS=XRETAIN_SECS						# Report the actual timeout value in the restore file
			fi
		fi


		RULENO=$(iptables -nvL INPUT --line | grep "lo " | awk '{print $1}')
		RULENO=$(($RULENO+1))

		iptables -D INPUT -m set $MATCH_SET Blacklist src -j DROP 2> /dev/null
		iptables -D INPUT -m set $MATCH_SET Whitelist src -j ACCEPT 2> /dev/null
		iptables -I INPUT $RULENO -m set $MATCH_SET Blacklist src -j DROP
		iptables -I INPUT $RULENO -m set $MATCH_SET Whitelist src -j ACCEPT
		if [ "$?" -gt 0 ];then
		   RC=$?
		   logger -st "($(basename $0))" $$  "**ERROR** Unable to add - INPUT $MATCH_SET Whitelist RC="$RC
		   echo -e "\a`iptables -nvL INPUT --line >> /tmp/syslog.log`" 
		fi
		
		# Use original 'logdrop' chain or custom 'Blacklist' chain etc.
		if [ $USE_LOGDROP -eq 1 ];then														# Use 'logdrop' chain
			iptables -D logdrop -m state --state NEW -j SET --add-set Blacklist src 2> /dev/null
			iptables -I logdrop -m state --state NEW -j SET --add-set Blacklist src
		else																					# Use 'Blacklist' chain
			# Delete previous Blacklist rules
			iptables -D INPUT -i $(nvram get wan0_ifname) -m state --state INVALID -j Blacklist 2> /dev/null		#WAN only
			iptables -D INPUT                                -m state --state INVALID -j Blacklist 2> /dev/null
			iptables -D INPUT -j Blacklist 2> /dev/null
			iptables -D FORWARD ! -i br0 -o $(nvram get wan0_ifname) -j Blacklist 2> /dev/null
			iptables -D FORWARD   -i $(nvram get wan0_ifname) -m state --state INVALID -j Blacklist  2> /dev/null

			# Use a custom CHAIN 'Blacklist' rather than 'logdrop'
			iptables -F Blacklist
			iptables -X Blacklist
			iptables -N Blacklist
			iptables -I Blacklist -m state --state NEW -j SET --add-set Blacklist src
			if [ "$NOLOG" == "0" ];then					# Suppress 'Block =' messages from syslog? 0-Create;1-Suppress
				iptables -A Blacklist -m state --state NEW -j LOG --log-prefix "Block " --log-tcp-sequence --log-tcp-options --log-ip-options
			fi
			# Let other following rule issue the actual DROP or not!!!???
			#iptables -A Blacklist -j DROP
			
			RULELIST=

			RULENO=$( iptables --line -nvL INPUT | grep "state RELATED,ESTABLISHED" | cut -d" " -f1)
			RULENO=$(($RULENO+1))

			# WAN only or ALL interfaces BRx / tun1x etc. ?
			#if [ $WAN_ONLY ];then
				#iptables -I INPUT $RULENO -i $(nvram get wan0_ifname) -m state --state INVALID -j Blacklist		# WAN only
			#else
				iptables -I INPUT $RULENO                             -m state --state INVALID -j Blacklist			# ALL interfaces
			#fi

			RULELIST=$RULELIST""$RULENO" "

			RULENO=$(iptables --line -nvL INPUT | grep -cE "^[1-9]")			# Count of existing rules in INPUT chain
			iptables -I INPUT $RULENO -j Blacklist								# Penultimate in the INPUT chain

			RULELIST=$RULELIST""$RULENO" "

			#logger -st "($(basename $0))" $$ "***DEBUG Blacklist rules @"$RULELIST"inserted into INPUT chain"

			RULELIST=

			RULENO=$( iptables --line -nvL FORWARD | grep "DROP       all  --  !br0   eth0" | cut -d" " -f1)
			iptables -I FORWARD $RULENO ! -i br0 -o $(nvram get wan0_ifname) -j Blacklist

			RULELIST=$RULELIST""$RULENO" "

			RULENO=$(iptables --line -nvL FORWARD | grep "DROP       all  --  eth0   *" | cut -d" " -f1)
			iptables -I FORWARD $RULENO -i $(nvram get wan0_ifname) -m state --state INVALID -j Blacklist

			RULELIST=$RULELIST""$RULENO" "

			#logger -st "($(basename $0))" $$ "***DEBUG Blacklist rules @"$RULELIST"inserted into FORWARD chain"

		fi

		# Add LAN subnet to Whitelist IPSET ?
		ipset -q $ADD Whitelist `nvram get lan_ipaddr`/24
		
		# Remember to manually include all VLANs e.g. 10.0.0.0/8 see /jffs/configs/IPSET_Whitelist


		logger -st "($(basename $0))" $$  "Dynamic IPSET Blacklist banning enabled."

		if [ -f /jffs/scripts/HackerPorts.sh ]; then
			logger -st "($(basename $0))" $$ "Hacker Port Activity report scheduled every 06:05 daily"
			/usr/sbin/cru a HackerReport "5 6 * * * /jffs/scripts/HackerPorts.sh"
		fi

esac

# Allow dynamic Disable of Syslog messages
if [ "$NOLOG" == "0" ];then					# Suppress 'Block =' messages from syslog? 0-Create;1-Suppress
	if [ "$1" != "init" -a -z "$(iptables --line -L Blacklist | grep "state NEW LOG")" ];then		# Enable if it doesn't exist
		iptables -A Blacklist -m state --state NEW -j LOG --log-prefix "Block " --log-tcp-sequence --log-tcp-options --log-ip-options
		echo -e "\a\tSyslog 'Block =' messages enabled\n"
	fi
else																			# Suppress if it exists
	if [ ! -z "$(iptables --line -L Blacklist | grep "state NEW LOG")" ];then
		iptables -D Blacklist -m state --state NEW -j LOG --log-prefix "Block " --log-tcp-sequence --log-tcp-options --log-ip-options
		echo -e "\a\n\tSyslog 'Block =' messages suppressed"
	fi
fi

# Summary

if [ ! -s "$bannedips" ]; then 
   OLDAMOUNT=0
   LAST_MOD=
else
   LAST_MOD=$(ls -l $bannedips | grep -oE "root.*/tmp" | sed 's/root//' | sed 's/\/tmp//' | sed -e 's/^[ \t]*//' | cut -d' ' -f2-)
   OLDAMOUNT=$(cat "$bannedips")
fi

if [ $(ipset -L Blacklist | grep -E "^[0-9]" | wc -l) -gt 0 ]; then
	ipset -L Blacklist | grep -E "^[0-9]" | wc -l > $bannedips
	NEWAMOUNT=$(cat $bannedips)
else
	NEWAMOUNT=0
fi
DELTA=$(($NEWAMOUNT-$OLDAMOUNT))
if [ $DELTA -lt 0 ];then
	DELTA=$(echo "$DELTA" | sed 's/-//')
	UP_DOWN="expired"
else
	UP_DOWN="added"
fi
INTERVAL=
if [ ! -z "$LAST_MOD" ];then
	INTERVAL="since: "$LAST_MOD
fi

HITS=$(iptables --line -nvL INPUT | grep -E "set.*Blacklist" | awk '{print $2}')
if [ -z $HITS ];then
	HITS=0
fi

TEXT="\033[00mSummary Blacklist: \e[42m$HITS Successful blocks!\033[00m ( \e[41m$OLDAMOUNT IPs currently banned - $DELTA $UP_DOWN\033[00m $INTERVAL)\033[00m"
TEXT2="Summary Blacklist: $HITS Successful blocks! ( $OLDAMOUNT IPs currently banned - $DELTA $UP_DOWN $INTERVAL)"

XRETAIN_SECS=$(ipset $LIST Blacklist | head -n 4 | grep -E "^Header" | grep -oE "timeout.*" | cut -d" " -f2)
if [ ! -z "$XRETAIN_SECS" ];then	
	TEXT=$TEXT", Entries auto-expire after "$(Convert_SECS_to_HHMMSS $XRETAIN_SECS)" hrs"
fi

echo -e "\n\t"$TEXT"\n"
logger -t "($(basename $0))" $$ $TEXT2


exit 0
