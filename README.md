# certwatch

I'll be making a Python package for this in a short while, with command line parameters for enabling the different options, and proper documentation.

In the meantime, here's a standalone version.

To use it, you must first install the following Python packages:
* pip install cryptography
* pip install prettytable
* pip install tqdm

Then launch the program with a filename parameter telling it about a list of hostname / ports to check certificates on (an example is provided).

The program establishes a TLS connection with each of those hostnames / ports and loads their certificate using the Server Name Information (SNI) feature of the TLS protocol.

As it doesn't "talk" any application protocol it's able to deal with https, smtps, nntps, ldaps, ftps, imaps, pop3s or whatever communication protocol using X509 certificates...

A list of certificates sorted by nearest expiration date is then printed.
