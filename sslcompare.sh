#!/bin/bash

# SSL Checker 0.4
# Written by Angel Nieves
# Compares resulting SSL certificate between cURL and OpenSSL

# Exit Codes
# 0 = Certificates match
# 1 = Certificates don't match
# 2 = Certificate(s) expired
# 3 = Invalid arguments supplied
# 4 = Domain does not resolve
# 5 = Connection timed out
# 6 = Connection refused

DOMAIN='';
PORT='';
EXPIRED='0';
RESULTONLY='0';

RESULT='';

TIMEOUT='10';

# Converts exit code into boolean
# $1 = Exit Code
# $2 = Reverse Color (boolean of 1 or 0)
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

# Add 0 to date to ensure it may be compared
# $1 = Date input
function ParseDate()
{
	if [[ -n $(echo "$1" | grep -E '^.{3}\s{2}[0-9]\s') ]]; then # Mon  0 
		echo $1 | awk '{$2 = "0"$2; print $0}';
	elif [[ -n $(echo "$1" | grep -E '^.{3}\s[0-9]{2}\s') ]]; then # Mon 00 
		echo $1;
	fi
}

# Return if date has been passed
# $1 = Expiration date in 'date' format
function CheckExpired()
{
	curdateNix=$(date +%s);
	expdateNix=$(date -d "$1" +%s);
	
	test $curdateNix -ge $expdateNix;
	return $?;
}

# Return whether or not the certificates match
function Main()
{
	# Establish cURL and OpenSSL connections
	curlErr=$(curl -svI "https://$DOMAIN:$PORT" --connect-timeout "$TIMEOUT" 2>&1 > /dev/null); curlCode=$?;
	opensslOut=$(echo | timeout "$TIMEOUT" openssl s_client -connect "$DOMAIN:$PORT" 2> /dev/null); opensslCode=$?;
	
	## Abort if connection was made to a URL that didn't load
	if [ $curlCode == '28' -o $opensslCode == '124' ]; then
		echo "Connection to https://$DOMAIN:$PORT timed out!";
		return 4;
	elif [ $curlCode == '7' -o $opensslCode == '1' ]; then
		echo "Connection to https://$DOMAIN:$PORT was refused!";
		return 5;
	fi
	# End cURL/OpenSSL connections
	
	# cURL and OpenSSL variable dump
	startDate=$(ParseDate "$(echo "$curlErr" | awk -F': ' '/start date/ {print $2}')");
	expDate=$(ParseDate "$(echo "$curlErr" | awk -F': ' '/expire date/ {print $2}')");
	commonN=$(echo "$curlErr" | awk -F': ' '/common name/ {print $2}');
	rawgroup=$(echo "$curlErr" | awk -F',O=' '/issuer:/ {print $2}' | awk -F',.=' '{print $1}');
	parsegroup=$(echo "$rawgroup" | sed 's/"//g'); # Used to remove " characters from "cPanel, Inc."
	expired=$(CheckExpired "$expDate"; echo $?);
	_startDate=$(ParseDate "$(echo "$opensslOut" | openssl x509 -noout -dates | awk -F'=' '/notBefore/ {print $2}')");
	_expDate=$(ParseDate "$(echo "$opensslOut" | openssl x509 -noout -dates | awk -F'=' '/notAfter/ {print $2}')");
	_commonN=$(echo "$opensslOut" | awk -F'CN=' '/subject/ {print $2}');
	_group=$(echo "$opensslOut" | awk -F'O=' '/issuer/ {print $2}' | awk -F'/' '{print $1}');
	_expired=$(CheckExpired "$_expDate"; echo $?);
	# End variable dump
	
	#Output cURL and OpenSSL results
	echo -e "\e[2mcURL Results\e[0m";
	echo "Common Name: $commonN";
	echo "Organization: $parsegroup";
	echo -e "Expired: $(CodeToBool $expired 1)\n Start: $startDate\n End: $expDate";
	echo -e "\n\e[2mOpenSSL Results\e[0m";
	echo "Common Name: $_commonN";
	echo "Organization: $_group";
	echo -e "Expired: $(CodeToBool $_expired 1)\n Start: $_startDate\n End: $_expDate";
	#End cURL and OpenSSL results
	
	# Compare between cURL and OpenSSL output
	mismatch=$(test $commonN != $_commonN -o "$parsegroup" != "$_group" -o "$startDate" != "$_startDate" -o "$expDate" != "$_expDate"; echo $?);
	__expired=$(test $EXPIRED == '1' -a $expired == '0' -o $EXPIRED == '1' -a $_expired == '0'; echo $?);
	
	printf "\n\e[2mComparison Results\e[0m: ";
	if [ $mismatch == '0' ]; then
		# Failure
		echo 'Different';
		RESULT='1';
	else
		# Success
		echo -e '\e[32mSame\e[0m';
		RESULT='0';
	fi
	
	echo "Common Name: $(CodeToBool $(test $commonN == $_commonN; echo $?) 0)";
	echo "Organization: $(CodeToBool $(test "$parsegroup" == "$_group"; echo $?) 0)";
	echo "Expired: $(CodeToBool $(test $expired == $_expired; echo $?) 0)";
	echo " Start: $(CodeToBool $(test "$startDate" == "$_startDate"; echo $?) 0)";
	echo " End: $(CodeToBool $(test "$expDate" == "$_expDate"; echo $?) 0)";
	# End comparison
	
	if [ $__expired == '0' ]; then
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