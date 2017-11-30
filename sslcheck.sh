#!/bin/bash

# SSL Checker
# Written by Angel N.
#
# Wrapper for openssl s_client/x509 used to retrieve SSL information.
# Also supports certificates from stdin.

# User Variables
HOST='';			# -h --host
NAME='';			# -n --name
PORT='443';			# -p --port
PROTOCOL='';		# --protocol
USESNI='1';			# --nosni
SAN='0';			# --san
FORMAT='PEM';		# --format
TIMEOUT='10';		# --timeout

# General Variables
SNICOMP='1';		# Compatible with SNI
TIMEOUTCOMP='1';	# Has coreutil timeout
HOSTISIP='0';		# Supplied host is IP

# Miscellaneous Variables
readonly VERSION='1.01';
readonly VERSIONDATE='November 30 2017';

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
	local expdatenix=$(date -d "${1}" +'%s');
	
	[ ${curdatenix} -ge ${expdatenix} ];
	return ${?};
}

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
	if [ ${1} == '0' -a ${2} == '0' ]; then
		echo -e "\e[32mTrue\e[0m";
	elif [ ${1} == '0' -a ${2} == '1' ]; then
		echo -e "\e[31mTrue\e[0m";
	elif [ ${1} -gt '0' -a ${2} == '0' ]; then
		echo -e '\e[31mFalse\e[0m';
	elif [ ${1} -gt '0' -a ${2} == '1' ]; then
		echo -e '\e[32mFalse\e[0m';
	fi
}

# Checks to see what aspects of the script the server is compatible with.
#
# Parameters: None
#
# Return
# 0 - Script can execute
# 1 - Script cannot execute
function CompatibilityCheck()
{
	# Check to see if OpenSSL can be found. If not, exit the script.
	[ "$(which openssl 2> /dev/null)" ] || return 1;
	
	# Grab the current version of OpenSSL.
	local opensslver=$(openssl version | awk '{print $2}' | cut -d'-' -f1);
	
	# Multiple checks are run to parse the OpenSSL version.
	# 1. Check if the OpenSSL major version is below 1.0.0
	# 2. Check if the OpenSSL excludes 0.9.8
	# 3. Check if the last letter is "below" f (e.g. 0.9.8e)
	if [[ $(cut -d'.' -f1 <<< "${opensslver}") != '1' ]] && \
	[[ -z $(grep '0.9.8' <<< "${opensslver}") || \
	$(tail -c 2 <<< "${opensslver}" | tr '[a-e]' '[1-6]' | grep -E '[1-6]') ]]; then
		# SNI is not supported
		SNICOMP='0';
		USESNI='0';
	else
		# SNI is supported
		SNICOMP='1';
	fi
	
	# Check to see if GNU coreutil timeout is installed.
	[ "$(timeout --version 2> /dev/null)" ] || TIMEOUTCOMP='0';
}

# Pass script arguments.
#
# Parameters
# $1 - $@
#
# Return
# 0 - n/a
# 1 - Help was shown
function ParseArgs()
{
	while [[ ${#} -gt '0' ]]
	do
		case ${1} in
			-h|--host)
				if ParseArgs_IsValid "${2}"; then
					# Used as part of s_client -connect.
					HOST=${2};
					
					# Check if provided argument is an IP.
					[[ ${HOST} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && HOSTISIP='1';
				fi
				shift;
				;;
			-n|--name)
				if ParseArgs_IsValid "${2}"; then
					# Used as part of s_client -servername.
					# Set $NAME provided the server is compatible with SNI.
					[ ${SNICOMP} == '0' ] && echo 'Server does not support SNI, no servername will be specified.' || NAME=${2};
				fi
				shift;
				;;
			-p|--port)
				if ParseArgs_IsValid "${2}" && [[ ${2} =~ ^[0-9]+$ ]]; then
					# Used as part of s_client -connect.
					PORT=${2};
				fi
				shift;
				;;
			--protocol)
				if ParseArgs_IsValid "${2}" && \
				[[ ${2} == 'smtp' || ${2} == 'pop3' || ${2} == 'imap' || ${2} == 'ftp' || ${2} == 'xmpp' ]]; then
					# Used with s_client -starttls.
					# Certain services require STARTTLS to be issued before a TLS connection.
					PROTOCOL=${2};
				fi
				shift;
				;;
			--nosni)
				# Notify user if SNI is not supported on the server.
				[ ${SNICOMP} == '0' ] && echo 'Server does not support SNI, no servername will be specified.' || USESNI='0';
				shift;
				;;
			--san)
				# Retrieve Subject Alternative Name from certificate.
				[ ${SAN} != '1' ] && SAN='1';
				shift;
				;;
			--format)
				if ParseArgs_IsValid "${2}" && [[ ${2} == 'DER' || ${2} == 'NET' ]]; then
					# Used with x509 -inform.
					FORMAT=${2};
				fi
				shift;
				;;
			--timeout)
				if ParseArgs_IsValid "${2}" && [[ ${2} =~ ^[0-9]+$ ]]; then
					# Modify script's timeout period.
					[ ${TIMEOUTCOMP} == '0' ] \
						&& echo 'Server does not have timeout installed, unable to define custom timeout period.' \
						|| TIMEOUT=${2};
				fi
				shift;
				;;
			--help)
				ShowHelp '0';
				return 1;
				;;
			*)
				shift;
				;;
		esac
	done
}

# Check if passed argument is valid.
#
# Parameters
# $1 - Argument
#
# Return
# 0 - Valid
# 1 - Invalid 
function ParseArgs_IsValid()
{
	[[ ${1} && "$(cut -c'1' <<< ${1})" != '-' ]];
	return ${?};
}

# Pass standard input to X509_DisplayInfo().
# 
# Parameters: None
#
# Return
# 0 - Success
# 7 - Failure
function ParseStdin()
{
	# Parse standard input using openssl.
	local opensslvar=$(openssl x509 -inform ${FORMAT} -in /dev/stdin 2> /dev/null);
	
	# If the parsed input is returned as blank, exit.
	[ -z "${opensslvar}" ] && { echo -e 'Received invalid value from stdin. (error 7)\nVerify the certificate you are using is valid.'; return 7; };
	
	# Output SSL information and exit script.
	X509_DisplayInfo "${opensslvar}" '1';
	return 0;
}

# Establishes s_client connection to host and port.
#
# Parameters
# $1 - Host
# $2 - Port
# $3 - Name
#
# Return
# See SClient_ErrorParse()
function SClient_Connect()
{
	# Compile the openssl s_client command based off of all the options/input provided so far.
	# Store the output into a variable to manually check if any errors occurred.
	local connectionstr=$(echo -n '' | $([ ${TIMEOUTCOMP} == '1' ] && echo -n "timeout ${TIMEOUT}") openssl s_client -connect "${1}:${2}"$([[ -n ${PROTOCOL} ]] && echo -n " -starttls ${PROTOCOL}")$([[ -n ${3} ]] && echo " -servername ${3}") -showcerts 2>&1);
	
	# If there's an error, return the error code from SClient_ErrorParse().
	SClient_ErrorParse "${connectionstr}" || return ${?};
	
	# No error, return the s_client output.
	echo "${connectionstr}";
}

# Checks the s_client connection for errors.
#
# Parameters
# $1 - openssl s_client
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
	[[ ${TIMEOUTCOMP} == '1' && -z ${1} ]] && { echo "Connection to ${HOST}:${PORT} timed out! (error 3)"; return 3; };
	
	# Error catching for specific errors. If no error is found, function returns 0 and proceeds with the script.
	if grep -E ":errno=|:error:|didn't found starttls" <<< "${1}" > /dev/null; then
		# Connection was refused.
		grep 'socket: Connection refused' <<< "${1}" > /dev/null && { echo "Connection to ${HOST}:${PORT} was refused! (error 2)"; return 2; };
		
		# Connection timed out.
		grep 'socket: Connection timed out' <<< "${1}" > /dev/null && { echo "Connection to ${HOST}:${PORT} timed out! (error 3)"; return 3; };
		
		# Unknown protocol.
		grep 'SSL23_GET_SERVER_HELLO:unknown protocol' <<< "${1}" > /dev/null && { echo "Unknown protocol received from ${HOST}:${PORT}! (error 4)\nTry specifying a protocol using --protocol."; return 4; };
		
		# Unknown/generic error.
		echo "Unknown error encountered when connecting to ${HOST}:${PORT}! (error 1)";
		return 1;
	fi
}

# Shows help page.
#
# Parameters
# $1 - Boolean toggle determining whether or not to show full help (0 = full, 1 = short)
#
# Return: None
function ShowHelp()
{
	[ ${1} == '0' ] && echo -e "\e[97mNAME\e[0m
\tSSL Checker ${VERSION}
\tUpdated ${VERSIONDATE}

\e[97mDESCRIPTION\e[0m
\tScript used for checking for the presence of an SSL certificate on a hostname or IP
\tAlso can interpret a valid x509 certificate from standard input
";
	
	echo -e "\e[97mREQUIRED OPTIONS\e[0m
\t-h --host <host>	Specify a domain name or IP secured by SSL

\e[97mOPTIONAL CONNECTION OPTIONS\e[0m
\t-p --port <port>	Specify the port that is secured by SSL, uses 443 if not specified
\t-n --name <hostname>	Specify a specific domain name to receive from the host
\t--protocol <protocol>	Specify a protocol to use in the connection (smtp, pop3, imap, ftp, xmpp)
\t--nosni			Retrieves the SSL certificate without specifying a servername
\t--san			Get Subject Alternative Name for certificate

\e[97mOTHER OPTIONS\e[0m
\t--timeout		Define timeout for the s_client connection
\t--help			Show this help menu as well as exit codes

\e[97mSTANDARD INPUT\e[0m
\t--format		Specify the encoding on a certificate from standard input (DER, NET)

\tExample of using standard input:
	bash < cert
	cat cert | bash";
	
	[ ${1} == '0' ] && echo -e "
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

# Return various aspects of an X.509 certificate in human readable form.
# All of these functions share the same parameters.
#
# Parameters
# $1 - openssl s_client/x509
#
# Return: None
function X509_Cert() { openssl x509 <<< "${1}"; }
function X509_CommonName() { openssl x509 -noout -subject <<< "${1}" | awk -F'CN=' '{print $2}' | awk -F'/.+=' '{print $1}'; }
function X509_EndDate() { openssl x509 -noout -enddate <<< "${1}" | cut -d'=' -f2; }
function X509_Fingerprint() { openssl x509 -noout -fingerprint <<< "${1}" | cut -d'=' -f2; }
function X509_IsEV() { openssl x509 -noout -subject <<< "${1}" | grep '/serialNumber=' > /dev/null; return $?; }
function X509_Issuer() { openssl x509 -noout -issuer <<< "${1}" | awk -F'O=' '{print $2}' | awk -F'/.+=' '{print $1}'; return $?; }
function X509_Organization() { openssl x509 -noout -subject <<< "${1}" | awk -F'O=' '{print $2}' | awk -F'/.+=' '{print $1}'; return $?; }
function X509_StartDate() { openssl x509 -noout -startdate <<< "${1}" | cut -d'=' -f2; }
function X509_Chain()
{
	local basecert=$(X509_Cert "${1}");
	local fullchain=$(awk '/-----BEGIN/,/-----END/' <<< "${1}");
	
	# If the chain is just the base certificate, then exit function.
	[[ "${basecert}" == "${fullchain}" ]] && return 0;
	
	echo "${1}" | awk -v certidx=-1 '
	/-----BEGIN CERTIFICATE-----/ {inc=1; certidx++}
	inc {if (certidx > 0) print}
	/-----END CERTIFICATE-----/ {inc=0}
	';
}
function X509_SubjectAltName()
{
	local sanlist;
	
	for name in $(openssl x509 -noout -text <<< "${1}" | grep 'DNS:');
	do
		sanlist+="$(echo $name | cut -d':' -f2 | cut -d',' -f1)\n";
	done
	
	echo -e ${sanlist};
}
function X509_Revoked()
{
	# Get main certificate and certificate chain. If certificate chain is empty, exit the function.
	local maincert=$(X509_Cert "${1}");
	local certchain=$(X509_Chain "${1}");
	[[ -z ${certchain} ]] && return 2;
	
	# Get OCSP URL. If it does not exist, exit the function.
	local ocspurl=$(openssl x509 -noout -ocsp_uri <<< "${1}");
	[[ -z ${ocspurl} ]] && return 2;
	
	local ocspresponse=$(openssl ocsp -issuer <(echo "${certchain}") -cert <(echo "${maincert}") -url ${ocspurl} -text -header "Host" "$(echo ${ocspurl} | awk -F'://' '{print $2}')" 2>&1);
	
	grep -i 'OCSP Response Status: successful' <<< "${ocspresponse}" > /dev/null || return 2;
	grep -i 'Cert Status: revoked' <<< "${ocspresponse}" > /dev/null && return 0 || return 1;
}

# Converts output of s_client or x509 into neat text.
#
# Parameters
# $1 - openssl s_client/x509
# $2 - stdin Boolean
#
# Return: None
function X509_DisplayInfo()
{
	local commonname=$(X509_CommonName "${1}");
	local altnames=$(X509_SubjectAltName "${1}");
	local issuer=$(X509_Issuer "${1}");
	local organization=$(X509_Organization "${1}");
	local startdate=$(date -d "$(X509_StartDate "${1}")" +'%b %d %G %r %Z');
	local enddate=$(date -d "$(X509_EndDate "${1}")" +'%b %d %G %r %Z');
	[[ ${2} == '0' && -n ${issuer} ]] && local revoked=$(X509_Revoked "${1}"; echo $?);
	local fingerprint=$(X509_Fingerprint "${1}");
	
	# Create and display header.
	[ ${2} == '0' ] && {
		local servername=$([[ ${USESNI} == '1' && -n ${NAME} ]] && echo -n " (${NAME})");
		local ip=$([ ${HOSTISIP} != '1' ] && echo -n " - $(dig ${HOST} +short | head -1)");
		printf "\e[2m%s:%s%s%s\e[0m\n" ${HOST} ${PORT} "${servername}" "${ip}"; };
	
	[[ -z ${commonname} ]] && echo -e 'Common Name: \e[31mNone\e[0m' || echo "Common Name: ${commonname}";
	echo -e "Subject Alternative Name(s):$([[ ${SAN} == '1' && -n ${altnames} ]] && echo "${altnames}" | sed 's/^/ /' || echo " $([[ -n ${altnames} ]] && echo "${altnames}" | wc -l || echo '0') Name(s)")";
	[[ -z ${issuer} ]] && echo -e "Issuer: \e[31mSelf-signed\e[0m" || echo "Issuer: ${issuer}";
	echo "Expired: $(CodeToBool $(CheckExpired "${enddate}"; echo ${?}) 1)
 Start: ${startdate}
 End: ${enddate}";
	[[ ${revoked} && ${revoked} != '2' ]] && echo "Revoked: $(CodeToBool ${revoked} 1)";
	[[ $(X509_IsEV "${1}"; echo ${?}) == '0' && -n ${organization} ]] && echo -e "Extended Validation: \e[32mTrue\e[0m\n Organization: ${organization}";
	echo "Fingerprint: ${fingerprint}";
}

# Main function of the script.
function Main()
{
	# Check to see if the script is compatible.
	CompatibilityCheck || { echo 'OpenSSL not found in $PATH variable.'; return 1; };
	
	# Load all passed arguments to the script first.
	ParseArgs "${@}" || return 0;
	
	# If standard input was provided, parse it.
	[[ ! -t 0 && -t 1 ]] && { ParseStdin; return ${?}; };
	
	
	
	# If standard input was not provided, check to see if a hostname was.
	# If not, then exit the script and show the help page.
	[ -z "${HOST}" ] && { ShowHelp '1'; return 6; };
	
	# If SNI is being used, ensure servername has a value.
	[[ ${USESNI} == '1' && -z ${NAME} && ${HOSTISIP} == '0' ]] && NAME=${HOST};
	
	# Create s_client connection and exit script if errors are returned.
	local s_client_exit='0';
	S_CLIENT_VAR=$(SClient_Connect "${HOST}" "${PORT}" "${NAME}") || s_client_exit=${?};
	[ ${s_client_exit} != '0' ] && { echo -e "${S_CLIENT_VAR}"; return ${s_client_exit}; };
	
	# Output SSL information.
	X509_DisplayInfo "${S_CLIENT_VAR}" '0';
}

Main "${@}";
exit ${?};