#!/bin/bash

# Active SSL Compare 0.3
# Written by Angel Nieves - April 30 2017
# Compares resulting SSL certificate between curl and openssl

# Exit Codes
# 0 = Certificates match
# 1 = Certificates don't match
# 2 = Invalid arguments supplied
# 3 = Domain does not resolve
# 4 = Connection timed out
# 5 = Connection refused

DOMAIN='';
PORT='';
RESULTONLY='';

RESULT='';

TIMEOUT='10';

function ParseDate()
{
	if [[ -n $(echo "$1" | grep -E '^.{3}\s{2}[0-9]\s') ]]; then # Mon  0 
		echo $1 | awk '{$2 = "0"$2; print $0}';
	elif [[ -n $(echo "$1" | grep -E '^.{3}\s[0-9]{2}\s') ]]; then # Mon 00 
		echo $1;
	fi
}

# Return whether or not the certificates match
function Main()
{
	# Curl
	curlErr=$(curl -svI "https://$DOMAIN:$PORT" --connect-timeout "$TIMEOUT" 2>&1 >/dev/null);
	
	# Abort if connection is made to a URL that won't load
	if [[ -n $(echo $curlErr | grep -E 'Connection timed out after .+ milliseconds') ]]; then
		echo "Connection to https://$DOMAIN:$PORT timed out!";
		return 4;
	elif [[ -n $(echo $curlErr | grep 'Connection refused') ]]; then
		echo "Connection to https://$DOMAIN:$PORT was refused!";
		return 5;
	fi
	
	startDate=$(ParseDate "$(echo "$curlErr" | awk -F': ' '/start date/ {print $2}')");
	expDate=$(ParseDate "$(echo "$curlErr" | awk -F': ' '/expire date/ {print $2}')");
	commonN=$(echo "$curlErr" | awk -F': ' '/common name/ {print $2}');
	rawgroup=$(echo "$curlErr" | awk -F',O=' '/issuer:/ {print $2}' | awk -F',.=' '{print $1}');
	parsegroup=$(echo "$rawgroup" | sed 's/"//g'); # Used to remove " characters from cPanel, Inc.
	
	echo -e "curl Results";
	echo -e " Common Name: $commonN";
	echo -e " Organization: $parsegroup";
	if [[ $rawgroup != $parsegroup ]]; then
		echo -e "  Raw: $rawgroup";
	fi
	echo -e " Start: $startDate\n End: $expDate";

	
	# OpenSSL
	opensslOut=$(echo | openssl s_client -connect "$DOMAIN:$PORT" 2> /dev/null);
	_startDate=$(ParseDate "$(echo | openssl s_client -connect "$DOMAIN:$PORT" 2> /dev/null | openssl x509 -noout -dates | awk -F'=' '/notBefore/ {print $2}')");
	_expDate=$(ParseDate "$(echo | openssl s_client -connect "$DOMAIN:$PORT" 2> /dev/null | openssl x509 -noout -dates | awk -F'=' '/notAfter/ {print $2}')");
	_commonN=$(echo "$opensslOut" | awk -F'CN=' '/subject/ {print $2}');
	_group=$(echo "$opensslOut" | awk -F'O=' '/issuer/ {print $2}' | awk -F'/' '{print $1}');
	
	echo -e "\nopenssl Results\n Common Name: $_commonN\n Organization: $_group\n Start: $_startDate\n End: $_expDate";
	
	# Return comparison
	echo -e "\nResults";
	
        if [[ $commonN == $_commonN ]]; then
                echo " Common Name: True/Good";
        else
                echo " Common Name: False/Bad";
        fi
	if [[ $parsegroup == $_group ]]; then
                echo " Organization: True/Good";
        else
                echo " Organization: False/Bad";
	fi
	if [[ $(echo $startDate | sed 's/ //g') == $(echo $_startDate | sed 's/ //g') ]]; then
		echo " Start Date: True/Good";
	else
		echo " Start Date: False/Bad";
	fi
	if [[ $(echo $expDate | sed 's/ //g') == $(echo $_expDate | sed 's/ //g') ]]; then
                echo " Expiry Date: True/Good";
        else
                echo " Expiry Date: False/Bad";
	fi


	if [[ $commonN != $_commonN || $parsegroup != $_group || $(echo $startDate | sed 's/ //g') != $(echo $_startDate | sed 's/ //g') || $(echo $expDate | sed 's/ //g') != $(echo $_expDate | sed 's/ //g') ]]; then
		# Failure
		RESULT='1';
	else
		# Success
		RESULT='0';
	fi
	echo "Final Result: $RESULT";
	
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
				if [[ $RESULTONLY == '1' ]]; then
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
                                if [[ $RESULTONLY == '1' ]]; then
                                        echo 2;
                                fi
                                exit 2;
                        fi
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

if [[ -n $DOMAIN || -n $PORT ]]; then
	# Make sure domain resolves.
	if [[ -z $(dig "$DOMAIN" +short) ]]; then
		if [[ $RESULTONLY == '1' ]]; then
			echo 3;
		fi
		exit 3;
	fi
	
	if [[ $RESULTONLY == '1' ]]; then
		Main > /dev/null;
		exitcode=$?;
		echo $exitcode;
		exit $exitcode;
	else
		Main;
	fi
fi
