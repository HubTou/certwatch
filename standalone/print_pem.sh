#!/bin/sh
if [ $# -ge "1" ]
then openssl x509 -inform PEM -in $1 -noout -text
fi
