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
VERSION='0.71';
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
# No return, echoes string
function GetNoSNI()
{
	# OpenSSL variable dump
	local nosni_cn=$(echo "$openssl_nosni" | openssl x509 -noout -subject | awk -F'CN=' '{print $2}' | awk -F'/.+=' '{print $1}');
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
	test $SAN == '1' && echo -e "$nosni_san";
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
	local sni_cn=$(echo "$openssl_sni" | openssl x509 -noout -subject | awk -F'CN=' '{print $2}' | awk -F'/.+=' '{print $1}');
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
	test $SAN == '1' && echo -e "$sni_san";
	[[ -z $sni_issuer ]] && echo -e "Organization: \e[31mSelf-signed\e[0m" || echo "Organization: $sni_issuer";
	echo -e "Expired: $(CodeToBool $sni_expired 1)\n Start: $sni_startdate\n End: $sni_enddate";
	#End OpenSSL results
}

function ShowHelp()
{
	echo -e "\e[97mNAME\e[0m
\tSSL Checker $VERSION

\e[97mREQUIRED ARGUMENTS\e[0m
\t-h|--host			Domain or IP secured by SSL

\e[97mOPTIONAL ARGUMENTS\e[0m
\t-p|--port			Port secured by SSL (default 443 if unspecified)
\t--output nosni|sni		Output one certificate specifically
\t--expired			Overwrite exit code with 2 if either certificate (if --output is not specified) is expired
\t--san				Get Subject Alternative Name for certificate
\t--help				Show this help menu.";
}

# GetStdConn()
# Establish standard OpenSSL connection
#
# Return
# 0 - No error
# 6 - Connection timed out
# 7 - Connection refused or unknown error
function GetStdConn()
{
	if [ $TIMEOUTCOMP == '1' ]; then
		openssl_nosni=$(echo | timeout $TIMEOUT openssl s_client -connect "$HOST:$PORT" 2>&1);
		local exitcode=$?;
		
		# Since timing out from the timeout binary won't trigger default OpenSSL timing out behavior, it has to be handled differently.
		# Ideally this shouldn't be triggered due to a ping check elsewhere in the code.
		if [[ -z $openssl_nosni && $exitcode = '124' ]]; then
			echo "Connection to $HOST:$PORT timed out!";
			return 6; # Exit script
		fi
	else
		openssl_nosni=$(echo | openssl s_client -connect "$HOST:$PORT" 2>&1);
		local exitcode=$?;
	fi
	
	if [ $(echo "$openssl_nosni" | grep 'connect:errno=') ]; then
		case $(echo "$openssl_nosni" | awk -F': ' '/socket:/ {print $2}') in
			'Connection refused')
				echo "OpenSSL connection to $HOST:$PORT was refused!";
				return 7;
			;;
			*)
				echo "Unknown error when connecting to $HOST:$PORT";
				return 7;
			;;
		esac
	fi
}

# GetSNIConn()
# Establish OpenSSL connection with SNI
#
# Return
# 0 - No error
# 6 - Connection timed out
# 7 - Connection refused or unknown error
function GetSNIConn()
{
	if [ $TIMEOUTCOMP == '1' ]; then
		openssl_sni=$(echo | timeout $TIMEOUT openssl s_client -connect "$HOST:$PORT" -servername $HOST 2>&1);
		local exitcode=$?;
		
		# Since timing out from the timeout binary won't trigger default OpenSSL timing out behavior, it has to be handled differently.
		# Ideally this shouldn't be triggered due to a ping check elsewhere in the code.
		if [[ -z $openssl_sni && $exitcode = '124' ]]; then
			echo "Connection to $HOST:$PORT timed out!";
			return 6; # Exit script
		fi
	else
		openssl_sni=$(echo | openssl s_client -connect "$HOST:$PORT" -servername $HOST 2>&1);
		local exitcode=$?;
	fi
	
	if [ $(echo "$openssl_sni" | grep 'connect:errno=') ]; then
		case $(echo "$openssl_sni" | awk -F': ' '/socket:/ {print $2}') in
			'Connection refused')
				echo "OpenSSL connection to $HOST:$PORT was refused!";
				return 7;
			;;
			*)
				echo "Unknown error when connecting to $HOST:$PORT";
				return 7;
			;;
		esac
	fi
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
	GetStdConn || return $?;
	if [ $SNICOMP == '1' ]; then
		GetSNIConn || return $?;
	fi
	
	
	local crtexpired='';
	if [ $OUTPUT ]; then
		# Execute OpenSSL connection
		test $OUTPUT == 'nosni' && GetNoSNI && crtexpired=$nosni_expired;
		test $OUTPUT == 'sni' && $SNICOMP == '1' && GetSNI && crtexpired=$sni_expired;
		
		# --output will only return whether or not the certificate was expired
		test $crtexpired == '0' && return '2' || return '3';
	else
		# Execute OpenSSL connections
		GetNoSNI;
		echo;
		test $SNICOMP == '1' && GetSNI;
		
		# Check if either certificate is expired
		crtexpired=$([[ $EXPIRED == '1' && $nosni_expired == '0' || $EXPIRED == '1' && $sni_expired == '0' ]]; echo $?);
		
		local RESULT='';
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

# CompatibilityCheck()
# Checks whether or not SNI is supported
# Also checks if the GNU coreutil timeout is installed
function CompatibilityCheck()
{
	local opensslver=$(openssl version | awk '{print $2}' | cut -d'-' -f1);
	
	# Check if the OpenSSL version is below 1.0
	# Check if the last character is LESS than f (which is when SNI became supported)
	# This includes the characters a-e (e.g. 0.9.8e)
	if [[ $(echo $opensslver | cut -d'.' -f1) != '1' && \
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

# Main code execution
CompatibilityCheck;

echo "\$SNICOMP = $SNICOMP";
echo "\$TIMEOUTCOMP = $TIMEOUTCOMP";

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
				if [ $2 == '80' ]; then
					echo 'Port 80 is not an allowed port.';
					exit 4;
				fi
				PORT=$2;
			fi
			shift;
			;;
		--output)
			if [ $2 ] && [ $2 == 'nosni' -o $2 == 'sni' ]; then
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
			ShowHelp;
			exit;
			;;
		*)
			# Unknown argument
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
	ShowHelp;
	exit 4;
fi