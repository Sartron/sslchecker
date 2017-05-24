#!/bin/bash

# SSL Checker 0.51
# Written by Angel Nieves
# Compares resulting SSL certificate between non-SNI & SNI

# Exit Codes
# 0 - Certificates match
# 1 - Certificates don't match
# 2 - Certificate(s) expired
# 3 - Invalid arguments supplied
# 4 - Domain does not resolve
# 5 - Connection timed out
# 6 - Connection refused or general failure

DOMAIN='';
PORT='';
EXPIRED='0';
RESULTONLY='0';

RESULT='';

TIMEOUT='10';

# Converts exit code into boolean
# $1 - Exit Code
# $2 - Reverse Color (boolean of 1 or 0)
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

# Return if date has been passed
# $1 - Expiration date in 'date' format
function CheckExpired()
{
	local curdatenix=$(date +%s);
	local expdatenix=$(date -d "$1" +%s);
	
	test $curdatenix -ge $expdatenix;
	return $?;
}

# Return whether or not the certificates match
function Main()
{
	# Establish OpenSSL connections
	# Setting these variables to local causes the exit code to return 0, they must remain global
	openssl_nosni=$(echo | timeout $TIMEOUT openssl s_client -connect "$DOMAIN:$PORT" 2> /dev/null); opensslexit=$?;
	openssl_sni=$(echo | timeout $TIMEOUT openssl s_client -connect "$DOMAIN:$PORT" -servername "$DOMAIN" 2> /dev/null); _opensslexit=$?;
	
	echo -e "$opensslexit\n$_opensslexit" | less;
	
	## Abort if connection was made to a URL that didn't load
	if [ $opensslexit == '124' -o $_opensslexit == '124' ]; then
		echo "Connection to $DOMAIN:$PORT timed out!";
		return 4;
	elif [ $opensslexit == '1' -o $_opensslexit == '1' ]; then
		echo "Connection to $DOMAIN:$PORT was refused or failed!";
		return 5;
	fi
	# End OpenSSL connections
	
	# OpenSSL variable dump
	local nosni_cn=$(echo "$openssl_nosni" | openssl x509 -noout -subject | awk -F'CN=' '{print $2}');
	local nosni_issuer=$(echo "$openssl_nosni" | openssl x509 -noout -issuer | awk -F'O=' '{print $2}' | awk -F'/CN=' '{print $1}');
	local nosni_startdate=$(date -d "$(echo "$openssl_nosni" | openssl x509 -noout -startdate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	local nosni_enddate=$(date -d "$(echo "$openssl_nosni" | openssl x509 -noout -enddate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	local nosni_expired=$(CheckExpired "$nosni_enddate"; echo $?);
	local nosni_fingerprint=$(echo "$openssl_nosni" | openssl x509 -noout -fingerprint | cut -d'=' -f2);
	
	local sni_cn=$(echo "$openssl_sni" | openssl x509 -noout -subject | awk -F'CN=' '{print $2}');
	local sni_issuer=$(echo "$openssl_sni" | openssl x509 -noout -issuer | awk -F'O=' '{print $2}' | awk -F'/CN=' '{print $1}');
	local sni_startdate=$(date -d "$(echo "$openssl_sni" | openssl x509 -noout -startdate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	local sni_enddate=$(date -d "$(echo "$openssl_sni" | openssl x509 -noout -enddate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	local sni_expired=$(CheckExpired "$sni_enddate"; echo $?);
	local sni_fingerprint=$(echo "$openssl_sni" | openssl x509 -noout -fingerprint | cut -d'=' -f2);
	# End variable dump
	
	#Output OpenSSL results
	echo -e "\e[2mOpenSSL Results\e[0m";
	echo "Common Name: $nosni_cn";
	echo "Organization: $nosni_issuer";
	echo -e "Expired: $(CodeToBool $nosni_expired 1)\n Start: $nosni_startdate\n End: $nosni_enddate";
	echo -e "\n\e[2mOpenSSL with SNI Results\e[0m";
	echo "Common Name: $sni_cn";
	echo "Organization: $sni_issuer";
	echo -e "Expired: $(CodeToBool $sni_expired 1)\n Start: $sni_startdate\n End: $sni_enddate";
	#End OpenSSL results
	
	# Compare separate OpenSSL requests
	local crtexpired=$(test $EXPIRED == '1' -a $nosni_expired == '0' -o $EXPIRED == '1' -a $sni_expired == '0'; echo $?);
	
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
}

# Main code execution
while [[ $# -gt 0 ]]
do
	arg=$1;
	case $arg in
		-d|--domain)
			_arg=$(echo "$2" | cut -c'1-2');
			if [[ $_arg != '--' && $_arg != '-' && -n $_arg ]]; then
				DOMAIN=$2;
			else
				# Program failed
				if [ $RESULTONLY == '1' ]; then
					echo 2;
				fi
				exit 2;
			fi
			shift
			;;
		-p|--port)
			_arg=$(echo "$2" | cut -c'1-2');
			if [[ $_arg != '--' && $_arg != '-' && -n $_arg ]]; then
				PORT=$2;
			else
				# Program failed
				if [ $RESULTONLY == '1' ]; then
					echo 2;
				fi
				exit 2;
			fi
			shift
			;;
		--expired)
			EXPIRED='1';
			shift
			;;
		--resultonly)
			RESULTONLY='1';
			shift
			;;
		*)
			# Unknown argument
			shift
			;;
	esac
done

if [[ -n $DOMAIN && -n $PORT ]]; then
	# Make sure domain resolves.
	if [ -z $(dig "$DOMAIN" +short) ]; then
		if [ $RESULTONLY == '1' ]; then
			echo 3;
		fi
		exit 3;
	fi
	
	if [ $RESULTONLY == '1' ]; then
		Main > /dev/null;
		exitcode=$?;
		echo $exitcode;
		exit $exitcode;
	else
		Main;
	fi
fi