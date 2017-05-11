#!/bin/sh
VER="v2.02"
#======================================================================================================= © 2016-2017 Martineau, v2.02
#
#      Report on Hacker attempts to attack local LAN ports. (Usually called by IPSET_Block.sh as part of its Summary display)
#      ('IPSET_Block.sh v3.xx' if 'nolog' arg is used then this script will NOT be able to report on the attacks!!!)
#      ('IPSET_Block.sh v4.xx' optionally uses an IPSET as a crude database for logging the hack attempts as well as, or in place of, Syslog messages) 
#
#      The console display report is also created to disk and allows double-clicking on the URLs to help identify the port being attacked and its attacker.
#
#     HackerPorts   [help | -h] | [file_name_for report] [verbose] [syslog] [num=nn]
#
#     HackerPorts
#                   Will produce a summary display of the top 10 in three categories: (unless default 'num=nn' has been specified)
#
#                   e.g. Thu Mar 9 13:31:11 DST 2017 Statistics: Total Unique Ports attacked: 31 (out of 324 attempts) tracked by SYSLOG between Mar 9 11:01 -
#
#                              Top 10 Ports attacked:
#                          4227 http://www.speedguide.net/port.php?port=23    e.g.  https://dnsquery.org/ipwhois/1.10.130.6
#                              <...>
#                              Top 10 attackers:
#                            3 https://dnsquery.org/ipwhois/52.174.156.242
#                              <...>
#                              Last 10 most recent attackers:
#                              https://dnsquery.org/ipwhois/146.185.239.117
#                              <...>
#
#     HackerPorts   verbose
#                   Will produce a summary display as above, but will also list ALL of the attacked ports and by whom! i.e. 324 in this example!!
#     HackerPorts   syslog num=25
#                   Will ignore the BlacklistTRK IPSET (if it exists) and use the Syslog attack messages and the top 25 (instead of 10) are listed. 
#
# https://dnsquery.org/ipwhois/ is FREE but not 100% accurate?, whereas https://www.whoisxmlapi.com/ is accurate but ONLY 20 FREE IP lookups per Guest

# Print between line beginning with '#==' to first blank line inclusive
ShowHelp() {
	awk '/^#==/{f=1} f{print; if (!NF) exit}' $0
}

# Function Parse(String delimiter(s) variable_names)
Parse() {
	#
	# 	Parse		"Word1,Word2|Word3" ",|" VAR1 VAR2 REST
	#				(Effectivley executes VAR1="Word1";VAR2="Word2";REST="Word3")
	
	local string IFS
 
	TEXT="$1"
	IFS="$2"
	shift 2
	read -r -- "$@" <<EOF
$TEXT
EOF
}
Tracking_Enabled () {

# Try and determine if Port tracking is enabled - either via Syslog or IPSET

	local STATUS=0									# 0-DISABLED,1-Syslog,2-IPSET,3-Both
	local FN=

	if [ ! -z "$(grep -iE "/jffs/scripts/IPSET_Block\.sh" /jffs/scripts/firewall-start | grep -vE "^\#")" ];then 
		if [ -z "$(grep -iE "/jffs/scripts/IPSET_Block\.sh.*nolog" /jffs/scripts/firewall-start)" ];then
			STATUS=1								# Yes Syslog i.e. 'nolog' wasn't specified
		else
			FN="/jffs/scripts/firewall-start"
		fi
	else
		if [ ! -z "$(grep -iE "/jffs/scripts/IPSET_Block\.sh" /jffs/scripts/services-start)" ];then 
			if [ -z "$(grep -iE "/jffs/scripts/IPSET_Block\.sh.*nolog" /jffs/scripts/services-start)" ];then
				STATUS=1							# Yes Syslog i.e. 'nolog' wasn't specified
			else
				FN="/jffs/scripts/services-start"
			fi
		fi
	fi
	
	if [ "$(ipset list BlacklistTRK 2> /dev/null | wc -l)" -gt 0 ]; then
		STATUS=$(($STATUS+2))						# Yes - IPSET
	fi
	
	echo $STATUS","$FN

}

Delete_TempFiles () {

	rm $LOGFILE".tmp" 2> /dev/null
	rm $LOGFILE".new" 2> /dev/null
	
	return 0
}

#==============================================Main=============================================

# Need assistance!???
if [ "$1" == "help" ] || [ "$1" == "-h" ]; then
	ShowHelp
	exit 0
fi

MYROUTER=$(nvram get computer_name)

if [ -d "/tmp/mnt/"$MYROUTER ];then
	MOUNT="/tmp/mnt/"$MYROUTER
else
	MOUNT="/tmp"
fi

if [ ! -z $1 ] && [ "$1" != "verbose" ] && [ -z $(echo $1 | grep -o "syslog") ] && [ -z $(echo $1 | grep -o "num=") ];then
	LOGFILE=$1
else
	LOGFILE=${MOUNT}/HackerReport.txt
fi

Delete_TempFiles

logger -st "($(basename $0))" $$ $VER "Hacker Port attacks Report starting....."

Parse "$(Tracking_Enabled)" "," TRACKING FN

if [ "$TRACKING" == "0" ];then
	echo -e "\a***ERROR Tracking not enabled? - check '"$FN"' 'IPSET_Block.sh init' was started"
	logger -t "($(basename $0))" $$ $VER "***ERROR Tracking not enabled? - check '"$FN"' 'IPSET_Block.sh init' was started"
	exit 97
fi

VERBOSE=0
if [ "$( echo $@ | grep -o "verbose" | wc -w )" -eq 1 ];then
	VERBOSE=1									# List ALL report lines rather than just the summary
fi

# How many attack items to be displayed in each category
TOPX=10
if [ "$( echo $@ | grep -o "num=" | wc -w )" -eq 1 ];then
	Parse "$( echo $@ | grep -oE "num=.*")" "=" v1 TOPX
	TOPX=$(echo $TOPX | cut -d" " -f1)						# Tacky! regexp should be used properly!
	TOPX=$(echo $TOPX | sed 's/ //g')						# Tacky! regexp should be used properly!
	if [ -z "$TOPX" ] || [ -z "${TOPX##*[!0-9]*}" ] || [ "$TOPX" -eq 0 ];then	# Must be only digits and not blank or '0'
		TOPX=1
		echo -e "\a\n\t\e[91m***Warning \e[5m'num='\e[25m directive invalid...num=1 assumed!\e[0m"
	fi
fi

# Does the Port tracker IPSET exist with at least 1 entry?
if [ "$(ipset list BlacklistTRK 2> /dev/null | wc -l)" -gt 7 ] && [ "$( echo $@ | grep -o "syslog" | wc -w )" -eq 0 ];then
	ipset list BlacklistTRK | grep -E "^[0-9]" | tr ",:" "  " | sort -nk3 | uniq -f2 -c | while read ITEM
		do
			Parse "$ITEM" " " PORTCNT SRC v3 PORT
			echo -e "$(printf "%5d %-45s e.g. %s" $PORTCNT "http://www.speedguide.net/port.php?port="$PORT )" "https://dnsquery.org/ipwhois/"$SRC >> $LOGFILE.tmp
		done
		DTYPE="IPSET"
		PERIODTXT=
else
	if [ "$TRACKING" == "1" ] || [ "$TRACKING" == "3" ] ;then
		# Extract the relevant Hacker attempt msgs (created by /jffs/scripts/IPSET_Block.sh etc.) from Syslog
		grep -E "[DROP IN=|Block IN=]$(nvram get wan0_ifname)" /tmp/syslog.log | grep -oE "SRC.*DPT=.*\SEQ" \
				| awk '{ print $1" " $(NF-1)}' | sort -t " " -nk 2.5n | uniq -f 1 -c \
				| sed -e 's/^[ \t]*//' | while read ITEM
			do
				Parse "$ITEM" " =" PORTCNT v2 SRC v4 PORT
				echo -e "$(printf "%5d %-45s e.g. %s" $PORTCNT "http://www.speedguide.net/port.php?port="$PORT )" "https://dnsquery.org/ipwhois/"$SRC >> $LOGFILE.tmp
			done
			DTYPE="SYSLOG"
			FIRSTTIMESTAMP=$(head -n 1 /tmp/syslog.log | cut -d" " -f1-4)
			LASTTIMESTAMP=$(tail -n 1 /tmp/syslog.log | cut -d" " -f1-4)
			PERIODTXT="between $FIRSTTIMESTAMP - $LASTTIMESTAMP"
	else
		echo -e "\a***ERROR Syslog Tracking DISABLED? - check '$FN' and change 'IPSET_Block.sh init nolog'"
		logger -t "($(basename $0))" $$ $VER "***ERROR Syslog Tracking DISABLED? - check '$FN' and change 'IPSET_Block.sh init nolog'"
		exit 98
	fi
fi 

UTOTAL=0;TOTAL=0
if [ -f ${LOGFILE}.tmp ];then
	UTOTAL=$(wc -l ${LOGFILE}.tmp | cut -d" " -f1)							# Unique Ports attacked
	TOTAL=$(awk -F' ' '{sum+=$1} END{print sum;}' ${LOGFILE}.tmp)		# Physical number of attacks
fi

TIMESTAMP=$(date)
echo -e "\n\n"$TIMESTAMP "Statistics: Total Unique Ports attacked:" $UTOTAL "(out of" $TOTAL "attempts) tracked using" $DTYPE $PERIODTXT  >> $LOGFILE.new	# New period's report Header
logger -t "($(basename $0))" $$ "Hacker report created '"$LOGFILE"' - Statistics: Total Unique Ports attacked:" $UTOTAL "(out of" $TOTAL "attempts) tracked using" $DTYPE

echo -e "\n\tTop $TOPX Ports attacked:" >> $LOGFILE.new
if [ -f ${LOGFILE}.tmp ];then
	head -n $TOPX $LOGFILE".tmp" | sort -nr     >> $LOGFILE.new
fi

echo -e "\n\tTop $TOPX attackers:"      >> $LOGFILE.new
if [ -f ${LOGFILE}.tmp ];then
	cat $LOGFILE".tmp" | uniq -f 3 -c | sort -nr | head -n $TOPX| awk '{printf "%5d %s\n", $1, $5}' >> $LOGFILE.new
fi

echo -e "\n\tLast $TOPX most recent attackers:" >> $LOGFILE.new 
if [ -f ${LOGFILE}.tmp ];then
	tail -n $TOPX $LOGFILE".tmp" | awk '{print "      "$4}'  >> $LOGFILE.new		# ...in chronological order last is 'most recent'
fi

cat $LOGFILE".new" >> $LOGFILE							# Update master report with this period's attack summary

echo -e "\n\tPorts attacked:" >> $LOGFILE
if [ -f ${LOGFILE}.tmp ];then
	cat $LOGFILE".tmp" >> $LOGFILE							# Update master report with this period's attack details
fi
# Show report just created ...either in FULL or just the summary.
if [ "$VERBOSE" == "1" ];then								# Just the summary report or ALL report details?
	awk -v pattern="${TIMESTAMP}" ' $0 ~ pattern { matched = 1 }; matched { print }' "$LOGFILE"		# Display ALL report lines
else
	echo -en "\e[1;31m"
	head -n 3 $LOGFILE.new									# Highlight the Summary header line in RED
	echo -e "\033[00m "
	tail -q -n +4 $LOGFILE.new							# Only display the new period's summary report
fi

echo -e

Delete_TempFiles


exit 0

