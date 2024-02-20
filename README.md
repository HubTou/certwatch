# Installation
Once you have installed [Python](https://www.python.org/downloads/) and its packages manager [pip](https://pip.pypa.io/en/stable/installation/),
use one of the following commands, depending on if you want only this tool, the full set of PNU tools, or PNU plus a selection of additional third-parties tools:

```
pip install pnu-certwatch
pip install PNU
pip install pytnix
```

# CERTWATCH(1)

## NAME
certwatch - watch X509 certificates expiration dates

## SYNOPSIS
**certwatch**
\[--delay|-d SEC\]
\[--excel|-e FILE\]
\[--filter|-f DAYS\]
\[--ip|-i\]
\[--new|-n\]
\[--noaltnames|-a\]
\[--noprogress|-b\]
\[--savedir|-s DIR\]
\[--timeout|-t SEC\]
\[--debug\]
\[--help|-?\]
\[--version\]
\[--\]
file [...]

## DESCRIPTION
The **certwatch** utility monitors [X509 certificates](https://en.wikipedia.org/wiki/X.509) expiration dates
by processing one or more data files containing lists of hostnames with optional port numbers.

It's mainly used to check the expiration date of [HTTPS](https://en.wikipedia.org/wiki/HTTPS) certificates (which is the default target when the port number is not indicated),
but the tool is protocol-agnostic and can "talk" to any SNI-aware ([Server Name Information](https://en.wikipedia.org/wiki/Server_Name_Indication)) [SSL/TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) server (smtps, imaps, ldaps, etc.)
without making too much assumptions on the correctness of servers certificates.

The certificates can be saved to a specified directory with the *--savedir|-s* option for further analysis with other tools (such as [OpenSSL](https://www.openssl.org/)).

As it's intended to bulk process a lot of certificates, a progress bar is displayed (can be removed with the *--noprogress|-b* option)
and the time allowed to get a certificate is limited to a 10 seconds timeout (can be specified otherwise with the *--timeout|-t* option).

In order to avoid doing a [Denial of Service attack](https://en.wikipedia.org/wiki/Denial-of-service_attack) on servers hosting many certificates, a 1 second delay is waited between each certificate request 
(can be specified otherwise with the *--delay|-d* option).

The tool results are presented as text tables.

The main one is the list of certificates successfully fetched, ordered by expiration date.
This list can be filtered with the *--filter|-f* option to only show certificates expired or expiring within the specified number of days.
You can use the *--noaltnames|-a* option in order to stop displaying alternate names contained in certificates,
or the *--ip|-i* option to include the IP addresses of servers.

The second table is the sorted list of hostnames / hostports where certificates couldn't be fetched,
with our best attempts to identify the reason why.

Two additional tables can be generated with the *--new|-n* option, in order to print the common names and alternate names
unmentioned in your input data files.

Finally, for user convenience, all these reports can be generated in a single multi-tabs Excel workbook specified with the *--excel|-e* option.

### OPTIONS
Options | Use
------- | ---
--delay\|-d SEC|Wait SEC (0-N) seconds between requests
--excel\|-e FILE|Output results in Excel FILE
--filter\|-f DAYS|Show results expiring in less than DAYS
--ip\|-i|Show IP address of hostnames
--new\|-n|Show unmentioned CN/alt names in input files
--noaltnames\|-a|Don't show alt names in results
--noprogress\|-b|Don't use a progress bar
--savedir\|-s DIR|Save certificates in DIR directory
--timeout\|-t SEC|Wait SEC (1-N) seconds before aborting a request
--debug|Enable debug mode
--help\|-?|Print usage and a short help message and exit
--version|Print version and exit
--|Options processing terminator

## ENVIRONMENT
The CERTWATCH_DEBUG environment variable can be set to any value to enable debug mode.

## FILES
[/usr/local/share/certwatch/tests.txt](https://github.com/HubTou/certwatch/blob/main/data/tests.txt) - config file example using the [badssl.com](https://badssl.com) Web site for testing live bogus X509 certificates

The structure of configuration files is as follows:
* Everything after a '#' character is a comment
* Blank lines are allowed
* data lines are either:
  * "hostname hostport"
  * "hostname"
* When hostport is not provided, port 443 (HTTPS) is assumed

## EXIT STATUS
The **certwatch** utility exits 0 on success, and >0 if an error occurs.

## EXAMPLES
The following command will make **certwatch** process your certificates list in *mycertslist.txt*,
save all certificates in PEM format to *mycertsdir*, print all possible reports and details to screen
and to an Excel workbook named *certwatch.out.xlsx*, and select or highlight certificates
expired or set to expire in the coming 30 days:
```Shell
# certwatch -in -e certwatch.out.xlsx -s mycertsdir -f 30 mycertslist.txt | tee certwatch.out.txt
```

Saved certificates can then be viewed with the **openssl** command like this for a *mycert.pem* file:
```Shell
# openssl x509 -inform PEM -in mycert.pem -noout -text | more
```

## SEE ALSO
[openssl(1)](https://www.openssl.org/docs/manmaster/man1/openssl.html)

## STANDARDS
The **certwatch** utility is not a standard UNIX command.

It tries to follow the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide for [Python](https://www.python.org/) code.

## PORTABILITY
To be tested under Windows.

## HISTORY
This implementation was made for the [PNU project](https://github.com/HubTou/PNU).

Both for my own needs and those of my company, I wanted an easy way to monitor thousands of certificates expiration dates.

The initial idea was to use the tool to send an email report of the certificates about to expire, but an Excel report in order to perform all kind of sorts and filtering was quickly necessary...

## LICENSE
It is available under the [3-clause BSD license](https://opensource.org/licenses/BSD-3-Clause).

## AUTHORS
[Hubert Tournier](https://github.com/HubTou)

## CAVEATS
Using this command through [outgoing proxies](https://en.wikipedia.org/wiki/Proxy_server) is untested and we provide no option to set the proxy address.
However it should work through reverse proxies on the server side.

## SECURITY CONSIDERATIONS
When certificate retrieval is unsuccessful, **certwatch** will try to diagnose the issue in different ways, one of which involving
running the system **[ping](https://en.wikipedia.org/wiki/Ping_(networking_utility))** command. This can be an issue if someone happens to place a command with the same name higher in your PATH.
But working at the IP layer level, which is needed in order to implement the [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) protocol, requires root privileges which I see as a bigger risk...
