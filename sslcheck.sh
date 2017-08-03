#!/bin/bash

# SSL Checker
# Written by Angel N.
# Wrapper for openssl s_client used to retrieve SSL information
# Also supports certificates from stdin

# User Options
HOST='';		# -h --host
NAME='';		# -n --name
PORT='443';		# -p --port
PROTOCOL='';	# --protocol
NOSNI='0';		# --nosni
SAN='0';		# --san
FORMAT='';		# --format
FORCE='0';		# --force

# Script Options
TIMEOUT='10';
VERSION='0.92';
VERSIONDATE='August 03, 2017';
SNICOMP='1';
TIMEOUTCOMP='1';
HOSTISIP='0';


# CodeToBool()
# Translate exit code into boolean with color
#
# Parameters
# $1 - Exit Code
# $2 - Inverse Color
#  0 - False
#  1 - True
# 
# Return: None
function CodeToBool()
{
	if [ $1 == '0' -a $2 == '0' ]; then
		echo -e "\e[32mTrue\e[0m";
	elif [ $1 == '0' -a $2 == '1' ]; then
		echo -e "\e[31mTrue\e[0m";
	elif [ $1 -gt '0' -a $2 == '0' ]; then
		echo -e '\e[31mFalse\e[0m';
	elif [ $1 -gt '0' -a $2 == '1' ]; then
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
	local curdatenix=$(date +'%s');
	local expdatenix=$(date -d "$1" +'%s');
	
	test $curdatenix -ge $expdatenix;
	return $?;
}

# X509_GetSAN()
# Output Subject Alternative Name
#
# Parameters
# $1 - OpenSSL base output
#
# Return: None
function X509_GetSAN()
{
	local base=$(echo "$1" | openssl x509 -noout -text | grep 'DNS:');
	local sancount=$(echo "$base" | grep -o 'DNS:' | wc -l);
	local san;
	
	for (( i = 1; i <= $sancount; i++ ))
	do
		san+=" $(echo $base | cut -d',' -f${i} | cut -d':' -f2)";
		test $i == $sancount || san+='\n';
	done
	
	test -z "$san" && echo -e 'Subject Alternative Name: \e[31mNone\e[0m'&& return 0;
	[[ -n $san && $SAN == '0' ]] && echo -e "Subject Alternative Name: $sancount Names" && return 0;
	echo -e "Subject Alternative Name: $sancount Names\n$san" && return 0;
}

# X509_Revoked()
# Retrieve revocation status of certificate using OCSP
function X509_Revoked()
{
	local ocspurl=$(echo "$1" | openssl x509 -noout -ocsp_uri);
	local crl=$(echo "$1" | openssl x509 -noout -text | awk '/CRL Distribution/,/URI/ { print $0 }' | awk -F'URI:' '/URI/ { print $2 }');
	
	#openssl s_client -status 2>&1 | grep -i 'ocsp'
	
	echo -e "Revoked: null\n OCSP URL: $ocspurl\n CRL: $crl";
}

# SClient_X509()
# Converts output of s_client into neat text
#
# Parameters
# $1 - s_client/x509 Input
# $2 - stdin Boolean
#
# Return: None
function SClient_X509()
{
	local cn=$(echo "$1" | openssl x509 -noout -subject | awk -F'CN=' '{print $2}' | awk -F'/.+=' '{print $1}');
	local san=$(X509_GetSAN "$1");
	local issuer=$(echo "$1" | openssl x509 -noout -issuer | awk -F'O=' '{print $2}' | awk -F'/.+=' '{print $1}');
	local startdate=$(date -d "$(echo "$1" | openssl x509 -noout -startdate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	local enddate=$(date -d "$(echo "$1" | openssl x509 -noout -enddate | cut -d'=' -f2)" +'%b %d %G %r %Z');
	local expired=$(CheckExpired "$enddate"; echo $?);
	local fingerprint=$(echo "$1" | openssl x509 -noout -fingerprint | cut -d'=' -f2);
	
	test "$2" == '0' && echo -e "\e[2m${HOST}:${PORT}$([[ $SNICOMP == '1' && $NOSNI != '1' && -n $NAME ]] && printf " ($NAME)"; test $HOSTISIP == '0' && echo " - $(dig $HOST +short | head -1)")\e[0m";
	#test $2 == '0' && echo -e "\e[2m${HOST}:${PORT}$()\e[0m";
	[[ -z $cn ]] && echo -e 'Common Name: \e[31mNone\e[0m' || echo "Common Name: $cn";
	echo -e "$san";
	[[ -z $issuer ]] && echo -e "Organization: \e[31mSelf-signed\e[0m" || echo "Organization: $issuer";
	echo -e "Expired: $(CodeToBool $expired 1)\n Start: $startdate\n End: $enddate";
	echo "Fingerprint: $fingerprint";
}

# SClient_ErrorParse()
# Checks the s_client connection for errors
#
# Parameters
# $1 - s_client/x509 Input
#
# Return
# 0 - No errors found
# 1 - Connection failed for unknown reason
# 2 - Connection was refused
# 3 - Connection timed out
# 4 - Connection received unknown protocol
function SClient_ErrorParse()
{
	# Check to see if the connection timed out when using timeout, and if so, exit.
	[[ $TIMEOUTCOMP == '1' && -z $1 ]] && echo "Connection to $HOST:$PORT timed out! (error 3)" && return 3;
	
	# Error catching for specific errors. If no error is found, function returns 0 and proceeds with the script.
	if [[ $(echo "$1" | grep -E ":errno=|:error:|didn't found starttls") ]]; then
		test "$(echo "$1" | grep 'socket: Connection refused')" && echo "Connection to $HOST:$PORT timed out! (error 3)" && return 3;
		test "$(echo "$1" | grep 'socket: Connection timed out')" && echo "Connection to $HOST:$PORT was refused! (error 2)" && return 2;
		test "$(echo "$1" | grep 'SSL23_GET_SERVER_HELLO:unknown protocol')" && \
			echo "Unknown protocol received from $HOST:$PORT! (error 4)\nTry specifying a protocol using --protocol." && return 4;
		
		echo "Unknown error encountered when connecting to $HOST:$PORT! (error 1)" && return 1; # Generic error
	fi
}

# SClientConnect()
# Establishes s_client connection to host and port
#
# Parameters
# $1 - Host
# $2 - Port
# $3 - Name
#
# Return
# See SClient_ErrorParse()
function SClientConnect()
{
	# Store output of s_client into variable.
	local connectionstr=$(echo |$(test $TIMEOUTCOMP == '1' && echo " timeout $TIMEOUT") openssl s_client -connect "${1}:${2}"$([[ -n $PROTOCOL ]] && echo " -starttls $PROTOCOL")$([[ -n $3 ]] && echo " -servername $3") -showcerts 2>&1);
	
	# If there's an error, return the error code from SClient_ErrorParse().
	SClient_ErrorParse "$connectionstr" || return $?;
	
	# No error, return the s_client output.
	echo "$connectionstr";
}

# Main()
# Establishes s_client connections and parses it
#
# Parameters: None
#
# Return: None
function Main()
{
	sclient=$(SClientConnect $HOST $PORT) || local sclient_exitcode=$?;
	test $SNICOMP == '1' && sclient_sni=$(SClientConnect $HOST $PORT $NAME) || sclient_sni_exitcode=$?;
	
	# SNI Connection
	if [[ $SNICOMP == '1' && $NOSNI != '1' ]] && [[ $HOSTISIP != '1' ]] || [[ $HOSTISIP == '1' && -n $NAME ]]; then
		test $sclient_sni_exitcode && echo -e "$sclient_sni" && return $sclient_sni_exitcode;
		SClient_X509 "$sclient_sni" '0' && return 0;
	fi
	
	# No SNI
	test $sclient_exitcode && echo -e "$sclient" && return $sclient_exitcode;
	SClient_X509 "$sclient" '0';
}

# ShowHelp()
# Shows help information
#
# Parameters
# $1 - Boolean toggle determining whether or not to show full help (0 = full, 1 = short)
#
# Return: None
function ShowHelp()
{
	test $1 == '0' && echo -e "\e[97mNAME\e[0m
\tSSL Checker $VERSION
\tUpdated $VERSIONDATE

\e[97mDESCRIPTION\e[0m
\tScript used for checking for the presence of an SSL certificate on a hostname or IP
\tAlso can interpret a valid x509 certificate from standard input
";

	echo -e "\e[97mREQUIRED ARGUMENTS\e[0m
\t-h --host <host>	Specify a domain name or IP secured by SSL

\e[97mOPTIONAL ARGUMENTS\e[0m
\t-p --port <port>	Specify the port that is secured by SSL, uses 443 if not specified
\t-n --name <hostname>	Specify a specific domain name to receive from the host
\t--protocol <protocol>	Specify a protocol to use in the connection (smtp, pop3, imap, ftp, xmpp)
\t--nosni			Retrieves the SSL certificate without specifying a servername
\t--san			Get Subject Alternative Name for certificate
\t--format		Specify the encoding on a certificate from standard input (DER, NET)
\t--force			Bypass script's ping check on the host
\t--help			Show this help menu as well as exit codes

\e[97mSTANDARD INPUT\e[0m
	bash < cert
	cat cert | bash";

	test $1 == '0' && echo -e "
\e[97mEXIT CODES\e[0m
\t0			Script executed successfully
\t1			Connection failed for unknown reason
\t2			Connection refused
\t3			Connection timed out
\t4			Connection received unknown protocol
\t5			Host did not respond
\t6			Invalid arguments supplied
\t7			stdin was invalid";
}

# CompatibilityCheck()
# Checks whether or not SNI is supported
# Also checks if the GNU coreutil timeout is installed
#
# Parameters: None
#
# Return: None
CompatibilityCheck()
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
	
	#Check for timeout compatibility by seeing if this command gets an error
	test "$(timeout --version 2> /dev/null)" || TIMEOUTCOMP='0';
}

# HandleArgs()
# Pass script arguments
#
# Parameters
# $1 - $@
#
# Return: None
function HandleArgs()
{
	while [[ $# -gt '0' ]]
	do
		case $1 in
			-h|--host)
				if [[ $2 && $(echo $2 | cut -c'1') != '-' ]]; then
					# Used as part of s_client -connect.
					HOST=$2;
					
					# Check if provided argument is an IP by getting output from dig.
					[[ -z $(dig $HOST +short) ]] && HOSTISIP='1';
				fi
				shift;
				;;
			-n|--name)
				if [[ $2 && $(echo $2 | cut -c'1') != '-' ]]; then
					# Used as part of s_client -servername.
					# Set $NAME provided the server is compatible with SNI.
					test $SNICOMP == '0' && echo 'Server does not support SNI, no servername will be specified.' || NAME=$2;
				fi
				shift;
				;;
			-p|--port)
				if [[ $2 && $(echo $2 | cut -c'1') != '-' ]]; then
					# Used as part of s_client -connect.
					PORT=$2;
				fi
				shift;
				;;
			--protocol)
				if [[ $2 && $(echo $2 | cut -c'1') != '-' ]] && \
				[[ $2 == 'smtp' || $2 == 'pop3' || $2 == 'imap' || $2 == 'ftp' || $2 == 'xmpp' ]]; then
					# Used with s_client -starttls.
					# Certain services require STARTTLS to be issued before a TLS connection.
					PROTOCOL=$2;
				fi
				shift;
				;;
			--nosni)
				# Notify user if SNI is not supported on the server.
				test $SNICOMP == '0' && echo 'Server does not support SNI, no servername will be specified.';
				NOSNI='1';
				shift;
				;;
			--san)
				# Retrieve Subject Alternative Name from certificate.
				SAN='1';
				shift;
				;;
			--format)
				if [[ $2 && $(echo $2 | cut -c'1') != '-' ]] && \
				[[ $2 == 'DER' || $2 == 'NET' ]]; then
					# Used with x509 -inform.
					FORMAT=$2;
				fi
				shift;
				;;
			--help)
				ShowHelp '0';
				exit;
				;;
			--force)
				# Used to bypass the ping check.
				FORCE='1';
				shift;
				;;
			*)
				# Skip argument.
				shift;
				;;
		esac
	done
}

# ParseStdin()
# Pass standard input to SClient_ErrorParse() and SClient_X509()
# 
# Parameters
# $1 - PEM/DER/NET certificate
#
# Return
# 0 - Success
# 7 - Failure
function ParseStdin()
{
	local stdin_x509=$(echo "$1" | openssl x509 2>&1);
	local exitcode=$(SClient_ErrorParse "$stdin_x509" > /dev/null; echo $?);
	test "$exitcode" == '0' && SClient_X509 "$stdin_x509" '1' && exit 0;
	test "$exitcode" != '0' && echo -e 'Unable to interpret value from stdin. (error 7)\nVerify the certificate you are using is valid.' && exit 7;
}

# Script pre-checks              #
# Check for script compatibility #
# Pass arguments to script       #
CompatibilityCheck;
HandleArgs "$@";
[[ -z $NAME && $HOSTISIP == '0' ]] && NAME=$HOST;

# Standard input needs to be held outside of a function in order to directly parse /dev/stdin
# Storing the input of a DER or NET file into a variable makes it unusable with openssl
if [[ ! -t 0 && -t 1 ]]; then
	[[ -n $FORMAT ]] && ParseStdin "$(openssl x509 -inform $FORMAT -in /dev/stdin 2> /dev/null)";
	ParseStdin "$(cat /dev/stdin)";
fi

# Script pre-check scompleted               #
# Proceed with default script functionality #
if [ -n "$HOST" ]; then
	if [ $(ping -c 1 -w 3 $HOST &> /dev/null; echo $?) != '0' ]; then
		# If --force is enabled, then ignore the fact that the ping failed.
		test $FORCE == '1' && echo "$HOST did not respond, but --force was passed." || echo -e "$HOST did not respond! (error 5)\nTry passing --force if host does resolve.";
		test $FORCE == '1' || exit 5;
	fi
	
	Main;
	exit $?;
else
	ShowHelp '1';
	exit 6;
fi