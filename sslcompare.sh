#!/bin/bash

# SSL Checker 0.6
# Written by Angel N.
# Check or compares resulting SSL certificate between non-SNI & SNI

# Launch Options
DOMAIN='';		# -d|--domain
PORT='';		# -p|--port
OUTPUT='';		# --output nosni|sni
EXPIRED='0';	# --expired
SAN='0';		# --san

# Static Option
TIMEOUT='10';

# Return
RESULT='';


# CodeToBool()
# Return 0 or 1 exit code as a boolean value with color
#
# Parameters
# $1 - Exit code
# $2 - Reverse color
# 
# No return, echoes string
function CodeToBool()
{
	if [ $1 == '0' -a $2 == '0' ]; then
		echo -e "\e[32mTrue\e[0m";
	elif [ $1 == '0' -a $2 == '1' ]; then
		echo -e "\e[31mTrue\e[0m";
	elif [ $1 == '1' -a $2 == '0' ]; then
		echo -e '\e[31mFalse\e[0m';
	elif [ $1 == '1' -a $2 == '1' ]; then
		echo -e '\e[32mFalse\e[0m';
	fi
}

# CheckExpired()
# Checks if SSL certificate is expired
#
# Parameters
# $1 - Expiration date in 'date' format
#
# Return
# 0 - Expired
# 1 - Not expired
function CheckExpired()
{
	local curdatenix=$(date +%s);
	local expdatenix=$(date -d "$1" +%s);
	
	test $curdatenix -ge $expdatenix;
	return $?;
}

# GetSAN()
# Output Subject Alternative Name
#
# Parameters
# $1 - OpenSSL base output
function GetSAN()
{
	local base=$(echo "$1" | openssl x509 -noout -text | grep 'DNS:');
	local sancount=$(echo "$base" | grep -o 'DNS:' | wc -l);
	local san='';
	
	for (( i = 1; i <= $sancount; i++ ))
	do
		san+=" $(echo $base | cut -d',' -f$i | cut -d':' -f2)";
		test $i == $sancount || san+='\n';
	done
	
	echo $san;
}

# GetNoSNI()
# Output information for an OpenSSL connection without using SNI
#
# No parameters, uses global variable
# 
# No return, echoes string
function GetNoSNI()
{
	# OpenSSL variable dump
	local nosni_cn=$(echo "$openssl_nosni" | openssl x509 -noout -subject | awk -F'CN=' '{print $2}');
	local nosni_san=$(GetSAN "$openssl_nosni");
	local nosni_issuer=$(echo "$openssl_nosni" | openssl x509 -noout -issuer | awk -F'O=' '{print $2}' | awk -F'/.+=' '{print $1}');
	local nosni_startdate=$(date -d "$(echo "$openssl_nosni" | openssl x509 -noout -startdate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	local nosni_enddate=$(date -d "$(echo "$openssl_nosni" | openssl x509 -noout -enddate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	nosni_expired=$(CheckExpired "$nosni_enddate"; echo $?);
	nosni_fingerprint=$(echo "$openssl_nosni" | openssl x509 -noout -fingerprint | cut -d'=' -f2);
	# End variable dump
	
	# Output OpenSSL results
	echo -e "\e[2mOpenSSL Results\e[0m";
	echo "Common Name: $nosni_cn";
	test $SAN == '1' && echo -e "Subject Alternative Name: $nosni_san";
	[[ -z $nosni_issuer ]] && echo -e "Organization: \e[31mSelf-signed\e[0m" || echo "Organization: $nosni_issuer";
	echo -e "Expired: $(CodeToBool $nosni_expired 1)\n Start: $nosni_startdate\n End: $nosni_enddate";
	#End OpenSSL results
}

# GetSNI()
# Output information for an OpenSSL connection using SNI
#
# No parameters, uses global variable
# 
# No return, echoes string
function GetSNI()
{
	# OpenSSL variable dump
	local sni_cn=$(echo "$openssl_sni" | openssl x509 -noout -subject | awk -F'CN=' '{print $2}');
	local sni_san=$(GetSAN "$openssl_sni");
	local sni_issuer=$(echo "$openssl_sni" | openssl x509 -noout -issuer | awk -F'O=' '{print $2}' | awk -F'/.+=' '{print $1}');
	local sni_startdate=$(date -d "$(echo "$openssl_sni" | openssl x509 -noout -startdate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	local sni_enddate=$(date -d "$(echo "$openssl_sni" | openssl x509 -noout -enddate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	sni_expired=$(CheckExpired "$sni_enddate"; echo $?);
	sni_fingerprint=$(echo "$openssl_sni" | openssl x509 -noout -fingerprint | cut -d'=' -f2);
	# End variable dump
	
	# Output OpenSSL results
	echo -e "\e[2mOpenSSL with SNI Results\e[0m";
	echo "Common Name: $sni_cn";
	test $SAN == '1' && echo -e "Subject Alternative Name: $sni_san";
	[[ -z $sni_issuer ]] && echo -e "Organization: \e[31mSelf-signed\e[0m" || echo "Organization: $sni_issuer";
	echo -e "Expired: $(CodeToBool $sni_expired 1)\n Start: $sni_startdate\n End: $sni_enddate";
	#End OpenSSL results
}

function ShowHelp()
{
	echo 'Required Arguments
-d|--domain			Domain secured by SSL
-p|--port			Port secured by SSL

Optional Arguments
--output nosni|sni		Output one certificate specifically
--expired			Overwrite exit code with 2 if either certificate (if --output is not specified) is expired
--san				Get Subject Alternative Name for certificate';
}

# Main()
# Establishes OpenSSL connections to domain and port
#
# Return
# 0 - Certificates match
# 1 - Certificates don't match
# 2 - Certificate(s) expired
function Main()
{
	# Establish OpenSSL connections
	# Setting these variables to local causes the exit code to return 0, they must remain global
	openssl_nosni=$(echo | timeout $TIMEOUT openssl s_client -connect "$DOMAIN:$PORT" 2> /dev/null); local opensslexit=$?;
	openssl_sni=$(echo | timeout $TIMEOUT openssl s_client -connect "$DOMAIN:$PORT" -servername $DOMAIN 2> /dev/null); local _opensslexit=$?;
	
	## Abort if connection was made to a URL that didn't load
	if [ $opensslexit == '124' -o $_opensslexit == '124' ]; then
		echo "Connection to $DOMAIN:$PORT timed out!";
		return 6;
	elif [ $opensslexit == '1' -o $_opensslexit == '1' ]; then
		echo "OpenSSL connection to $DOMAIN:$PORT was refused or failed!";
		return 7;
	fi
	# End OpenSSL connections
	
	local crtexpired='';
	if [ $OUTPUT ]; then
		# Execute OpenSSL connection
		test $OUTPUT == 'nosni' && GetNoSNI && crtexpired=$nosni_expired;
		test $OUTPUT == 'sni' && GetSNI && crtexpired=$sni_expired;
		
		# --output will only return whether or not the certificate was expired
		test $crtexpired == '0' && return '2' || return '3';
	else
		# Execute OpenSSL connections
		GetNoSNI;
		echo;
		GetSNI;
		
		# Check if either certificate is expired
		crtexpired=$([[ $EXPIRED == '1' && $nosni_expired == '0' || $EXPIRED == '1' && $sni_expired == '0' ]]; echo $?);
		
		printf "\n\e[2mFingerprint Match\e[0m: ";
		if [ $nosni_fingerprint != $sni_fingerprint ]; then
			# Failure
			echo -e '\e[31mFail\e[0m';
			RESULT='1';
		else
			# Success
			echo -e '\e[32mPass\e[0m';
			RESULT='0';
		fi
		# End comparison
		
		if [ $crtexpired == '0' ]; then
			RESULT='2';
		fi
		
		return $RESULT;
	fi
}

# Main code execution
while [[ $# -gt 0 ]]
do
	case $1 in
		-d|--domain)
			if [[ $2 && $(echo $2 | cut -c'1') != '-' ]]; then
				DOMAIN=$2;
			fi
			shift;
			;;
		-p|--port)
			if [[ $2 && $(echo $2 | cut -c'1') != '-' ]]; then
				PORT=$2;
			fi
			shift;
			;;
		--output)
			if [ $2 ] && [ $2 == 'nosni' -o $2 == 'sni' ]; then
				OUTPUT=$2;
			fi
			shift;
			;;
		--san)
			SAN='1';
			shift;
			;;
		--expired)
			EXPIRED='1';
			shift;
			;;
		*)
			# Unknown argument
			shift;
			;;
	esac
done

if [[ -n $DOMAIN && -n $PORT ]]; then
	# Make sure domain resolves
	if [ -z "$(dig $DOMAIN +short)" ]; then
		echo "$DOMAIN does not resolve to a valid IP!";
		exit 5;
	fi
	
	# Run script
	Main;
	exit $?;
else
	ShowHelp;
	exit 4;
fi