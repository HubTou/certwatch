# certwatch

I'll be making a Python package for this in a short while, with command line parameters for enabling the different options, and proper documentation.

In the meantime, here's a standalone version.

To use it, you must first install the following Python packages:
* pip install cryptography
* pip install prettytable
* pip install tqdm

Then launch the program with a filename parameter telling it about a list of hostname / ports to check certificates on (an [example](https://github.com/HubTou/certwatch/blob/main/standalone/errors.txt) is provided).

The program establishes a TLS connection with each of those hostnames / ports and loads their certificate using the [Server Name Information](https://en.wikipedia.org/wiki/Server_Name_Indication) (SNI) feature of the TLS protocol.

As it doesn't "talk" any application protocol it's able to deal with https, smtps, nntps, ldaps, ftps, imaps, pop3s or whatever communication protocol using X509 certificates...

A list of certificates sorted by nearest expiration date is then printed, as well as a list of common and alt names not mentioned in your input file.

## Todolist

* providing a filtering mechanism to only display certificates with less than X days before expiry
* support machine certificates for SSL
* may be offer a JSON output instead of a tabular one
* may be provide the builtin feature to display certificates (but it's so much better with OpenSSL)
