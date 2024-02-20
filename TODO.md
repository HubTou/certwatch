# certwatch TODOLIST

## Probable evolutions
* Providing results in some machine oriented format (csv, json, etc.)
* Use saved certificates as a cache when the file is recent and the expiration date is above a given threshold
* Replacing the "cryptography" module dependency with a library of our own focused on providing a decoded certificate as a Python dict (already being tested)

## Possible evolutions
* Option to use a proxy (--proxy|-p HOST[:PORT]). Could limit possible targets to HTTPS
* Option to display the hosting provider of the IP addresses (--hoster|-h). Would implies --ip|-i. I would like to use my pnu-whois tool for that, but I need to finish and publish it first!
* Option to group results (--group|-g) by:
  * issuer
  * IP address
  * hosting provider
  * CN

## Unprobable evolutions
* Colorization of results and option to disable it. Would need replacing the "prettytable" module. And, although fancy, not adapted to the intended emailing of results
* Option to display certificates. Already do-able (and done in pre-release versions), but better done with OpenSSL and not adapted to the bulk purpose of this tool
