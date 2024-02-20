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
certwatch - watch certificates expiration dates

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

## DESCRIPTION
The **certwatch** utility... TODO

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
/usr/local/share/certwatch/tests.txt - config file example

## EXIT STATUS
The **certwatch** utility exits 0 on success, and >0 if an error occurs.

## EXAMPLES
The following command will make **certwatch** process your certificates list in *mycertslist.txt*,
save all certificates in PEM format to *mycertsdir*, print all possible reports and details to screen
and to an Excel workbook named *certwatch.out.xlsx*, and select or highlight certificates
expired or set to expire in the coming 30 days.

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

## LICENSE
It is available under the [3-clause BSD license](https://opensource.org/licenses/BSD-3-Clause).

## AUTHORS
[Hubert Tournier](https://github.com/HubTou)

## CAVEATS
Using this command through outgoing proxies is untested and there is no option to set the proxy address.
However it should work through reverse proxies on the server side.

## SECURITY CONSIDERATIONS
When certificate retrieval is unsuccessful, **certwatch** will try to diagnose the issue in different ways, one of which involving
running the system **ping** command. This can be an issue if someone happens to place a command with the same name higher in your PATH.
But working at the IP layer level, which is needed in order to implement the ICMP protocol, requires root privileges which I see as a bigger risk...
