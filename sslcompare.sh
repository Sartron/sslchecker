#!/bin/bash

# SSL Checker
# Written by Angel N.
# Check or compares resulting SSL certificate between non-SNI & SNI

# Launch Options
HOST='';		# -h|--host
PORT='443';		# -p|--port
OUTPUT='';		# --output nosni|sni
EXPIRED='0';	# --expired
SAN='0';		# --san

# Static Option
TIMEOUT='10';
VERSION='0.82';
SNICOMP='1';
TIMEOUTCOMP='1';


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

# EstablishConn()
# Establish OpenSSL connection with SNI
#
# Parameters
# $1 - nosni|sni
#
# Return
# 0 - No error
# 6 - Connection timed out
# 7 - Connection refused or unknown error
function EstablishConn()
{
	local type=$1;
	
	if [ $TIMEOUTCOMP == '1' ]; then
		if [ $type == 'nosni' ]; then
			OPENSSL_NOSNI=$(echo | timeout $TIMEOUT openssl s_client -connect "$HOST:$PORT" 2>&1);
			local exitcode=$?;
			local opensslconn=$OPENSSL_NOSNI;
		elif [ $type == 'sni' ]; then
			OPENSSL_SNI=$(echo | timeout $TIMEOUT openssl s_client -connect "$HOST:$PORT" -servername $HOST 2>&1);
			local exitcode=$?;
			local opensslconn=$OPENSSL_SNI;
		fi
		
		# Since timing out from the timeout binary won't trigger default OpenSSL timing out behavior, it has to be handled differently.
		# Ideally this shouldn't be triggered due to a ping check elsewhere in the code.
		if [[ -z $opensslconn && $exitcode = '124' ]]; then
			echo "Connection to $HOST:$PORT timed out!";
			return 6; # Exit script
		fi
	else
		if [ $type == 'nosni' ]; then
			OPENSSL_NOSNI=$(echo | openssl s_client -connect "$HOST:$PORT" 2>&1);
			local exitcode=$?;
			local opensslconn=$OPENSSL_NOSNI;
		elif [ $type == 'sni' ]; then
			OPENSSL_SNI=$(echo | openssl s_client -connect "$HOST:$PORT" -servername $HOST 2>&1);
			local exitcode=$?;
			local opensslconn=$OPENSSL_SNI;
		fi
	fi
	
	# Error catching for socket/connection based errors.
	if [ $(echo "$opensslconn" | grep 'connect:errno=') ]; then
		case $(echo "$opensslconn" | awk -F': ' '/socket:/ {print $2}') in
			'Connection refused')
				echo "OpenSSL connection to $HOST:$PORT was refused!";
				return 7;
			;;
			*)
				echo "Unknown error when connecting to $HOST:$PORT!";
				return 7;
			;;
		esac
	fi
	
	# Generic error catching for non-socket/connection based errors.
	if [ -n "$(echo "$opensslconn" | grep -i ':error:')" ]; then
		if [ -n "$(echo "$opensslconn" | grep -i 'SSL23_GET_SERVER_HELLO:unknown protocol')" ]; then
			echo "Unknown protocol received when connecting to $HOST:$PORT!";
			return 7;
		fi
		echo -e "Unknown error when connecting to $HOST:$PORT!";
		return 7;
	fi
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
	
	test -n "$san" && echo "Subject Alternative Name:$san" || echo -e 'Subject Alternative Name: \e[31mNone\e[0m';
}

# GetNoSNI()
# Output information for an OpenSSL connection without using SNI
#
# No parameters, uses global variable
# 
# Returns whether or not certificate is expired.
function GetNoSNI()
{
	# OpenSSL variable dump
	local nosni_cn=$(echo "$OPENSSL_NOSNI" | openssl x509 -noout -subject | awk -F'CN=' '{print $2}' | awk -F'/.+=' '{print $1}');
	local nosni_san=$(GetSAN "$OPENSSL_NOSNI");
	local nosni_issuer=$(echo "$OPENSSL_NOSNI" | openssl x509 -noout -issuer | awk -F'O=' '{print $2}' | awk -F'/.+=' '{print $1}');
	local nosni_startdate=$(date -d "$(echo "$OPENSSL_NOSNI" | openssl x509 -noout -startdate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	local nosni_enddate=$(date -d "$(echo "$OPENSSL_NOSNI" | openssl x509 -noout -enddate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	local nosni_expired=$(CheckExpired "$nosni_enddate"; echo $?);
	NOSNI_FINGERPRINT=$(echo "$OPENSSL_NOSNI" | openssl x509 -noout -fingerprint | cut -d'=' -f2);
	# End variable dump
	
	# Output OpenSSL results
	echo -e "\e[2mOpenSSL Results\e[0m";
	[ -z $nosni_cn ] && echo -e 'Common Name: \e[31mNone\e[0m' || echo "Common Name: $nosni_cn";
	test $SAN == '1' && echo -e "$nosni_san";
	[[ -z $nosni_issuer ]] && echo -e "Organization: \e[31mSelf-signed\e[0m" || echo "Organization: $nosni_issuer";
	echo -e "Expired: $(CodeToBool $nosni_expired 1)\n Start: $nosni_startdate\n End: $nosni_enddate";
	# End OpenSSL results
	
	return $nosni_expired;
}

# GetSNI()
# Output information for an OpenSSL connection using SNI
#
# No parameters, uses global variable
# 
# Returns whether or not certificate is expired.
function GetSNI()
{
	# OpenSSL variable dump
	local sni_cn=$(echo "$OPENSSL_SNI" | openssl x509 -noout -subject | awk -F'CN=' '{print $2}' | awk -F'/.+=' '{print $1}');
	local sni_san=$(GetSAN "$OPENSSL_SNI");
	local sni_issuer=$(echo "$OPENSSL_SNI" | openssl x509 -noout -issuer | awk -F'O=' '{print $2}' | awk -F'/.+=' '{print $1}');
	local sni_startdate=$(date -d "$(echo "$OPENSSL_SNI" | openssl x509 -noout -startdate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	local sni_enddate=$(date -d "$(echo "$OPENSSL_SNI" | openssl x509 -noout -enddate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	local sni_expired=$(CheckExpired "$sni_enddate"; echo $?);
	SNI_FINGERPRINT=$(echo "$OPENSSL_SNI" | openssl x509 -noout -fingerprint | cut -d'=' -f2);
	# End variable dump
	
	# Output OpenSSL results
	echo -e "\e[2mOpenSSL with SNI Results\e[0m";
	[ -z $sni_cn ] && echo -e 'Common Name: \e[31mNone\e[0m' || echo "Common Name: $sni_cn";
	test $SAN == '1' && echo -e "$sni_san";
	[[ -z $sni_issuer ]] && echo -e "Organization: \e[31mSelf-signed\e[0m" || echo "Organization: $sni_issuer";
	echo -e "Expired: $(CodeToBool $sni_expired 1)\n Start: $sni_startdate\n End: $sni_enddate";
	# End OpenSSL results
	
	return $sni_expired;
}

# Main()
# Establishes OpenSSL connections to host and port
#
# Return
# 0 - Certificates match
# 1 - Certificates don't match
# 2 - Certificate(s) expired
function Main()
{
	# Establish OpenSSL connections
	EstablishConn 'nosni' || return $?;
	if [ $SNICOMP == '1' ]; then
		EstablishConn 'sni' || return $?;
	else
		# SNI not supported
		# Get standard OpenSSL connection and exit with status of expiration
		GetNoSNI && return 2 || return 3;
	fi
	
	if [ $OUTPUT ]; then
		# By default, the certificate is considered unexpired
		local crtexpired='1';
		
		# Execute OpenSSL output
		test $OUTPUT == 'nosni' && GetNoSNI && crtexpired=$?;
		test $OUTPUT == 'sni' && GetSNI && crtexpired=$?;
		
		# --output will only return whether or not the certificate was expired
		test $crtexpired == '0' && return '2' || return '3';
	else
		# By default, the certificates are considered unexpired
		local crtexpired='1';
		
		# Execute OpenSSL output
		GetNoSNI && crtexpired=$?;
		echo;
		GetSNI && crtexpired=$?;
		
		# Compare resulting fingerprints
		printf "\n\e[2mFingerprint Match\e[0m: ";
		if [ $NOSNI_FINGERPRINT != $SNI_FINGERPRINT ]; then
			# Failure
			echo -e '\e[31mFail\e[0m';
			test $EXPIRED == '0' && return 1;
		else
			# Success
			echo -e '\e[32mPass\e[0m';
			test $EXPIRED == '0' && return 0;
		fi
		
		# This code will only be triggered if $EXPIRED is set to 1
		test $crtexpired == '0' && return 2;
		test $crtexpired == '1' && return 3;
	fi
}

# ShowHelp()
# Shows help information
function ShowHelp()
{
	test $1 == '0' && echo -e "\e[97mNAME\e[0m
\tSSL Checker $VERSION

\e[97mDESCRIPTION\e[0m
\tScript used for checking for the presence of an SSL certificate on a hostname or IP
";

	echo -e "\e[97mREQUIRED ARGUMENTS\e[0m
\t-h|--host		Domain or IP secured by SSL

\e[97mOPTIONAL ARGUMENTS\e[0m
\t-p|--port		Port secured by SSL (default 443 if unspecified)
\t--output nosni|sni	Output one certificate specifically
\t--expired		Overwrite exit code with 2 if either certificate is expired
\t--san			Get Subject Alternative Name for certificate
\t--help			Show this help menu";

	test $1 == '0' && echo -e "
\e[97mEXIT CODES\e[0m
\t0			Returned certificates have matching fingerprints
\t1			Returned certificates do not have matching fingerprints
\t2			Returned certificate is expired
\t3			Returned certificate is not expired
\t4			Invalid script arguments supplied
\t5			Provided host does not resolve
\t6			Connection to host timed out
\t7			Connection to port refused or connection failed (generic)";
}

# CompatibilityCheck()
# Checks whether or not SNI is supported
# Also checks if the GNU coreutil timeout is installed
function CompatibilityCheck()
{
	local opensslver=$(openssl version | awk '{print $2}' | cut -d'-' -f1);
	
	# Multiple checks are run to parse the OpenSSL version
	# 1. Check if the OpenSSL major version is below 1.0.0
	# 2. Check if the OpenSSL excludes 0.9.8
	# 3. Check if the last letter is "below" f (e.g. 0.9.8e)
	if [[ $(echo $opensslver | cut -d'.' -f1) != '1' ]] && \
	[[ -z $(echo $opensslver | grep '0.9.8') || \
	$(echo $opensslver | tail -c 2 | tr '[a-e]' '[1-6]' | grep -E '[1-6]') ]]; then
		# SNI is not supported
		SNICOMP='0';
	else
		# SNI is supported
		SNICOMP='1';
	fi
	
	#Check for timeout compatibility
	test "$(timeout --version 2> /dev/null)" || TIMEOUTCOMP='0';
}

# Script begins here
CompatibilityCheck;
while [[ $# -gt 0 ]]
do
	case $1 in
		-h|--host)
			if [[ $2 && $(echo $2 | cut -c'1') != '-' ]]; then
				HOST=$2;
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
			if [[ $2 == 'nosni' || $2 == 'sni' ]]; then
				if [ $2 == 'sni' -a $SNICOMP == '0' ]; then
					# Exit script if server does not support SNI
					echo "Script cannot be executed with '--output sni' as the server does not support SNI!";
					exit 4;
				fi
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
		--help)
			ShowHelp '0';
			exit;
			;;
		*)
			shift;
			;;
	esac
done

if [ -n "$HOST" ]; then
	if [ $(ping -c 1 -w 3 $HOST &> /dev/null; echo $?) != '0' ]; then
		echo "$HOST does not resolve!";
		exit 5;
	fi
	
	# Run script
	Main;
	exit $?;
else
	ShowHelp '1';
	exit 4;
fi