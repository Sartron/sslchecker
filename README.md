# SSL Checker
Bash script designed to act as a wrapper for parsing OpenSSL.

## Usage
`bash <(curl -s https://raw.githubusercontent.com/Sartron/sslchecker/master/sslcheck.sh)`
* Required Options
    * `-h --host <host>`: Domain name or IP that the script will connect to.
* Optional Connection Options
	* `-p --port <port>`: Port that the script will connect to. By default, the script will connect to the host on port 443.
	* `-n --name <hostname>`: Specify a specific domain name you are checking for on the host. Only available on a server that supports SNI.
	* `--protocol <protocol>`: Specify a protocol to be used in the connection. Currently available: smtp, pop3, imap, ftp, xmpp
	* `--nosni`: Connect without specifying a specific servername. This is the default behavior assuming SNI is no supported.
	* `--san`: Output the _Subject Alternative Name_(s) for the certificate.
* Other Options	
	* `--timeout`: Define timeout period for the s_client connection. Only available provided the server has coreutils.
	* `--help`: Output the script's help information and exit the script.
* Standard Input
	* `--format <format>`: Specify the certificate's encoding that is being retrieved from standard input. Currently available: DER, NET
	* You may either pipe the output of a PEM-encoded certificate into the script or redirect input into the script.
	* To use NET or DER encoded certificates, you'll need to specify `--format DER|NET` which is documented above.

## Wiki
Visit the [wiki](https://github.com/Sartron/sslchecker/wiki) for further information.

## Issues
Please report any issues on the [issue page](https://github.com/Sartron/sslchecker/issues).