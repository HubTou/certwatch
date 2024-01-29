#!/usr/bin/env python3

import datetime
import os
import pprint
import re
import signal
import socket
import ssl
import sys
import time

import cryptography.x509
import cryptography.hazmat.backends
import cryptography.hazmat.primitives
import prettytable
import tqdm

####################################################################################################

def read_input_file():
    if len(sys.argv) < 2:
        print(f"USAGE: {sys.argv[0]} filename", file=sys.stderr)
        sys.exit(1)

    try:
        with open(sys.argv[1]) as file:
            lines = file.read().splitlines()
    except FileNotFoundError:
        print("ERROR: Filename doesn't exist", file=sys.stderr)
        sys.exit(1)

    return lines

####################################################################################################

def process_input_line(line):
    """
    The input line can be a blank line, a comment line (starting with #) or a data line:
        name [port] [# comment]
    Default port is 443 (https)
    """
    line = re.sub(r"#.*", "", line)
    line = line.strip()
    words = line.split()
    if len(words) == 0:
        raise Warning
    elif len(words) == 1:
        hostname = words[0]
        hostport = 443
    elif len(words) == 2:
        hostname = words[0]
        try:
            hostport = int(words[1])
        except ValueError:
            raise TypeError
        if hostport < 0 or hostport > 65535:
            raise ValueError
    else:
        raise SyntaxError

    return hostname, hostport

####################################################################################################

def add_items_to_dict(target_dict, extension):
    """
    A true parser would be better, but this one will do the job for the time being
    """
    group = re.match(r"^.*, name=([A-Za-z]+)\).*, value=<[A-Za-z]+\((.+)\)>\)>$", str(extension))
    if group == None:
        return

    if group[2].startswith("["):
        if group[1] == "authorityInfoAccess":
            name = ""
            value = re.sub(r"^\[", "", group[2])
            value = re.sub(r"\]$", "", value)
            target_dict[group[1]] = {}
            for part in value.split(", "):
                if part.startswith("name="):
                    part = re.sub(r"^name=", "", part)
                    name = re.sub(r"\).*$", "", part)
                elif part.startswith("access_location"):
                    part = re.sub(r"^access_location=<UniformResourceIdentifier\(value='", "", part)
                    part = re.sub(r"'.*$", "", part)
                    target_dict[group[1]][name] = part
        elif group[1] == "certificatePolicies":
            # Unmanaged!
            target_dict[group[1]] = group[2]
        elif group[1] == "extendedKeyUsage":
            value = re.sub(r"^\[", "", group[2])
            value = re.sub(r"\]$", "", value)
            target_dict[group[1]] = []
            for part in value.split(", "):
                if part.startswith("name="):
                    part = re.sub(r"^name=", "", part)
                    part = re.sub(r"\).*$", "", part)
                    target_dict[group[1]].append(part)
        elif group[1] == "signedCertificateTimestampList":
            target_dict[group[1]] = "A list of (uncollected) signed certificate timestamps"
        else:
            # Unmanaged!
            target_dict[group[1]] = group[2]
    elif group[2].startswith("<GeneralNames(["):
        value = re.sub(r"<GeneralNames\(\[", "", group[2])
        value = re.sub(r"\]\)>", "", value)
        value = re.sub(r"<DNSName\(value='", "", value)
        value = re.sub(r"'\)>", "", value)
        target_dict[group[1]] = []
        for part in value.split(", "):
            target_dict[group[1]].append(part)
    else:
        target_dict[group[1]] = {}
        for part in group[2].split(", "):
            key = part.split("=")[0]
            value = part.split("=")[1]
            if value in ["True", "False"]:
                target_dict[group[1]][key] = value == "True"
            elif value == "None":
                target_dict[group[1]][key] = None
            else:
                target_dict[group[1]][key] = value

####################################################################################################

def decode_pem_cert(pem_cert):
    certificate = {}

    cert = cryptography.x509.load_pem_x509_certificate(str.encode(pem_cert), cryptography.hazmat.backends.default_backend())

    version = {}
    version[cert.version.name] = cert.version.value
    certificate["version"] = version

    certificate["fingerprint"] = "0x" + cert.fingerprint(cryptography.hazmat.primitives.hashes.SHA256()).hex()
    certificate["serial number"] = cert.serial_number

    #public_key = cert.public_key()
    #print(f"public_key : {public_key}")

    certificate["not valid before"] = cert.not_valid_before_utc
    certificate["not valid after"] = cert.not_valid_after_utc

    issuer = {}
    for attribute in cert.issuer:
        issuer[attribute.oid._name] = attribute.value
    certificate["issuer"] = issuer

    subject = {}
    for attribute in cert.subject:
        subject[attribute.oid._name] = attribute.value
    certificate["subject"] = subject

    #print(f"signature_hash_algorithm : {cert.signature_hash_algorithm}")
    certificate["signature algorithm"] = cert.signature_algorithm_oid._name
    #print(f"signature_algorithm_parameters : {cert.signature_algorithm_parameters}")

    certificate["extensions"] = {}
    for extension in cert.extensions:
        add_items_to_dict(certificate["extensions"], extension)

    certificate["signature"] = "0x" + cert.signature.hex()

    return certificate

####################################################################################################

def get_cert(hostname, hostport, save_cert_dir):
    try:
        connection = ssl.create_connection((hostname, hostport))
    except socket.gaierror as error:
        raise NameError
    # There can also be a TimeoutError which will be caught in the calling function

    # We only test TLS connections and will fail on SSL ones
    # for example on https://null.badssl.com/ which uses SSLv3
    # because Server Name Indication (SNI) only works with TLS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    try:
        sock = context.wrap_socket(connection, server_hostname=hostname)
    except ssl.SSLError:
        raise ConnectionError

    der_cert = sock.getpeercert(True)
    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
    sock.close()

    if save_cert_dir:
        os.makedirs(save_cert_dir, exist_ok=True)
        filename = save_cert_dir + os.sep + hostname + "_" + str(hostport) + ".pem"
        with open(filename, "w") as file:
            file.write(pem_cert)

    return decode_pem_cert(pem_cert)

####################################################################################################

def timeout_signal_handler(signum, frame):
    raise TimeoutError

####################################################################################################

def get_certs(lines, progress_bar=True, delay=1, timeout=10, save_cert_dir=""):
    certs = {}
    signal.signal(signal.SIGALRM, timeout_signal_handler)
    if not progress_bar:
        for line in lines:
            try:
                hostname, hostport = process_input_line(line)
            except Warning:
                # empty line
                continue
            except TypeError:
                print("ERROR: invalid port number", file=sys.stderr)
                continue
            except ValueError:
                print("ERROR: invalid port value", file=sys.stderr)
                continue
            except SyntaxError:
                print("ERROR: invalid data line", file=sys.stderr)
                continue

            signal.alarm(timeout)
            try:
                cert = get_cert(hostname, hostport, save_cert_dir)
            except NameError:
                print(f"ERROR: hostname '{hostname}' doesn't seem to exist", file=sys.stderr)
                certs[hostname + ":" + str(hostport)] = None
                continue
            except TimeoutError:
                print(f"ERROR: hostname '{hostname}' doesn't seem to be listening on port {hostport}", file=sys.stderr)
                certs[hostname + ":" + str(hostport)] = None
                continue
            except ConnectionError:
                print(f"ERROR: hostname '{hostname}:{hostport}' doesn't accept the TLS protocol", file=sys.stderr)
                certs[hostname + ":" + str(hostport)] = None
                continue
            signal.alarm(0)
    
            certs[hostname + ":" + str(hostport)] = cert
    
            # Avoid doing a denial of service on target machines by spitting requests to fast
            time.sleep(delay)
    else:
        for i in tqdm.tqdm(range(len(lines))):
            try:
                hostname, hostport = process_input_line(lines[i])
            except Warning:
                # empty line
                continue
            except TypeError:
                print("ERROR: invalid port number", file=sys.stderr)
                continue
            except ValueError:
                print("ERROR: invalid port value", file=sys.stderr)
                continue
            except SyntaxError:
                print("ERROR: invalid data line", file=sys.stderr)
                continue
    
            signal.alarm(timeout)
            try:
                cert = get_cert(hostname, hostport, save_cert_dir)
            except NameError:
                print(f"ERROR: hostname '{hostname}' doesn't seem to exist", file=sys.stderr)
                certs[hostname + ":" + str(hostport)] = None
                continue
            except TimeoutError:
                print(f"ERROR: hostname '{hostname}' doesn't seem to be listening on port {hostport}", file=sys.stderr)
                certs[hostname + ":" + str(hostport)] = None
                continue
            except ConnectionError:
                print(f"ERROR: hostname '{hostname}:{hostport}' doesn't accept the TLS protocol", file=sys.stderr)
                certs[hostname + ":" + str(hostport)] = None
                continue
            signal.alarm(0)
    
            certs[hostname + ":" + str(hostport)] = cert
    
            # Avoid doing a denial of service on target machines by spitting requests to fast
            time.sleep(delay)

    return certs

####################################################################################################

def print_table(certs, show_alt_names=False):
    t = prettytable.PrettyTable()
    if show_alt_names:
        t.field_names = ["hostname:port", "common name", "alt name", "issuer org name", "not valid after"]
    else:
        t.field_names = ["hostname:port", "common name", "issuer org name", "not valid after"]
    t.align = "l"
    t.sortby = "not valid after"
    t.set_style(prettytable.SINGLE_BORDER)
    for key, value in certs.items():
        if value != None:
            try:
                common_name = value['subject']['commonName']
            except:
                common_name = ""
            try:
                alt_names = value['extensions']['subjectAltName']
            except:
                alt_names = []
            try:
                issuer = value['issuer']['organizationName']
            except:
                issuer = ""
            try:
                not_valid_after = value['not valid after']
            except:
                not_valid_after = datetime.datetime(1, 1, 1, 0, 0, 0, 0, tzinfo=datetime.timezone.utc)
            if show_alt_names:
                if len(alt_names):
                    for alt_name in alt_names:
                        t.add_row([key, common_name, alt_name, issuer, not_valid_after])
                else:
                    t.add_row([key, common_name, "", issuer, not_valid_after])
            else:
                t.add_row([key, common_name, issuer, not_valid_after])
        elif show_alt_names:
            t.add_row([key, "", "", "", datetime.datetime(1, 1, 1, 0, 0, 0, 0, tzinfo=datetime.timezone.utc)])
        else:
            t.add_row([key, "", "", datetime.datetime(1, 1, 1, 0, 0, 0, 0, tzinfo=datetime.timezone.utc)])

    print("\nCertificates expiration dates:")
    print(t)

####################################################################################################

def print_new_names(certs):
    hostnames = []
    common_names = []
    alt_names = []

    # build lists of unique values
    for key, value in certs.items():
        hostname = re.sub(r":.*$", "", key)
        if hostname not in hostnames:
            hostnames.append(hostname)
        if value != None:
            if 'subject' in value:
                if 'commonName' in value['subject']:
                    if value['subject']['commonName'] not in common_names:
                        common_names.append(value['subject']['commonName'])
            if 'extensions' in value:
                if 'subjectAltName' in value['extensions']:
                    for alt_name in value['extensions']['subjectAltName']:
                        if alt_name not in alt_names:
                            alt_names.append(alt_name)

    # build lists of new values
    new_common_names = []
    for common_name in common_names:
        if common_name not in hostnames:
            new_common_names.append(common_name)
    new_alt_names = []
    for alt_name in alt_names:
        if alt_name not in hostnames and alt_name not in common_names:
            new_alt_names.append(alt_name)

    # print what's new
    if new_common_names:
        print(f"\nCommon names unmentioned in your input files:")
        cn = prettytable.PrettyTable()
        cn.set_style(prettytable.SINGLE_BORDER)
        cn.add_column("common name", new_common_names)
        cn.align = "l"
        print(cn)

    if new_alt_names:
        print(f"\nAlt names unmentioned in your input files:")
        an = prettytable.PrettyTable()
        an.set_style(prettytable.SINGLE_BORDER)
        an.add_column("alt name", new_alt_names)
        an.align = "l"
        print(an)

####################################################################################################

lines = read_input_file()

certs = get_certs(lines)
#certs = get_certs(lines, save_cert_dir="certs")
#certs = get_certs(lines, delay=0, progress_bar=False, timeout=15, save_cert_dir="certs")

print_table(certs)
#print_table(certs, show_alt_names=True)

print_new_names(certs)

#pprint.pprint(certs)

