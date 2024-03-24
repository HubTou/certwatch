#!/usr/bin/env python3
""" certwatch - watch X509 certificates expiration dates
License: 3-clause BSD (see https://opensource.org/licenses/BSD-3-Clause)
Author: Hubert Tournier
"""

import getopt
import logging
import os
import sys

import libpnu

from .library import read_input_file, get_input_data, get_certs, print_table, generate_excel, \
                     get_new_names, print_new_names, update_excel

# Version string used by the what(1) and ident(1) commands:
ID = "@(#) $Id: certwatch - watch X509 certificates expiration dates v1.0.3 (March 24, 2024) by Hubert Tournier $"

# Default parameters. Can be overcome by environment variables, then command line options
parameters = {
    "Save cert dir": "",        # empty = don't save certificates
    "Delay": 1,                 # wait 0-N seconds between certificate requests to avoid DoS
    "Show progress": True,      # use a progress bar or not
    "Timeout": 10,              # wait 1-N seconds for a connection to succeed
    "Show alt names": True,     # show alternate names in the certificates or not
    "Show new names": False,    # show unmentioned common & alt names in your input file
    "Show IP address": False,   # show IP addresses of hostnames in results
    "Expiration days": None,    # only show results with an expiration date shorter than N days
    "Excel filename": "",       # empty = don't generate Excel results
}


####################################################################################################
def _display_help():
    """ Display usage and help """
    #pylint: disable=C0301
    print("usage: certwatch [--debug] [--help|-?] [--version]", file=sys.stderr)
    print("       [--delay|-d SEC] [--excel|-e FILE] [--filter|-f DAYS] [--ip|-i]", file=sys.stderr)
    print("       [--new|-n] [--noaltnames|-a] [--noprogress|-b] [--savedir|-s DIR]", file=sys.stderr)
    print("       [--timeout|-t SEC]", file=sys.stderr)
    print("       [--] filename [...]", file=sys.stderr)
    print("  ------------------  ---------------------------------------------------", file=sys.stderr)
    print("  --delay|-d SEC      Wait SEC (0-N) seconds between requests", file=sys.stderr)
    print("  --excel|-e FILE     Output results in Excel FILE", file=sys.stderr)
    print("  --filter|-f DAYS    Show results expiring in less than DAYS", file=sys.stderr)
    print("  --ip|-i             Show IP address of hostnames", file=sys.stderr)
    print("  --new|-n            Show unmentioned CN/alt names in input files", file=sys.stderr)
    print("  --noaltnames|-a     Don't show alt names in results", file=sys.stderr)
    print("  --noprogress|-b     Don't use a progress bar", file=sys.stderr)
    print("  --savedir|-s DIR    Save certificates in DIR directory", file=sys.stderr)
    print("  --timeout|-t SEC    Wait SEC (1-N) seconds before aborting a request", file=sys.stderr)
    print("  --debug             Enable debug mode", file=sys.stderr)
    print("  --help|-?           Print usage and this help message and exit", file=sys.stderr)
    print("  --version           Print version and exit", file=sys.stderr)
    print("  --                  Options processing terminator", file=sys.stderr)
    print(file=sys.stderr)
    #pylint: enable=C0301


####################################################################################################
def _process_environment_variables():
    """ Process environment variables """
    #pylint: disable=C0103, W0602
    global parameters
    #pylint: enable=C0103, W0602

    if "CERTWATCH_DEBUG" in os.environ:
        logging.disable(logging.NOTSET)

    logging.debug("_process_environment_variables(): parameters:")
    logging.debug(parameters)


####################################################################################################
def _process_command_line():
    """ Process command line options """
    #pylint: disable=C0103, W0602
    global parameters
    #pylint: enable=C0103, W0602

    # option letters followed by : expect an argument
    # same for option strings followed by =
    character_options = "abd:e:f:ins:t:?"
    string_options = [
        "delay=",
        "excel=",
        "filter=",
        "ip",
        "new",
        "noaltnames",
        "noprogress",
        "savedir=",
        "timeout=",
        "debug",
        "help",
        "version",
    ]

    try:
        options, remaining_arguments = getopt.getopt(
            sys.argv[1:], character_options, string_options
        )
    except getopt.GetoptError as error:
        logging.critical("Syntax error: %s", error)
        _display_help()
        sys.exit(1)

    for option, argument in options:

        if option == "--debug":
            logging.disable(logging.NOTSET)

        elif option in ("--help", "-?"):
            _display_help()
            sys.exit(0)

        elif option == "--version":
            print(ID.replace("@(" + "#)" + " $" + "Id" + ": ", "").replace(" $", ""))
            sys.exit(0)

        elif option in ("--delay", "-d"):
            try:
                parameters["Delay"] = int(argument)
            except ValueError:
                logging.critical("--delay|-d parameter must be an integer value")
                sys.exit(1)
            if parameters["Delay"] < 0:
                logging.critical("--delay|-d parameter must be an positive value")
                sys.exit(1)

        elif option in ("--excel", "-e"):
            if not argument.endswith(".xlsx"):
                logging.critical("--excel|-e parameter must use a .xlsx extension")
                sys.exit(1)
            parameters["Excel filename"] = argument

        elif option in ("--filter", "-f"):
            try:
                parameters["Expiration days"] = int(argument)
            except ValueError:
                logging.critical("--filter|-f parameter must be an integer value")
                sys.exit(1)

        elif option in ("--ip", "-i"):
            parameters["Show IP address"] = True

        elif option in ("--new", "-n"):
            parameters["Show new names"] = True

        elif option in ("--noaltnames", "-a"):
            parameters["Show alt names"] = False

        elif option in ("--noprogress", "-b"):
            parameters["Show progress"] = False

        elif option in ("--savedir", "-s"):
            parameters["Save cert dir"] = argument

        elif option in ("--timeout", "-t"):
            try:
                parameters["Timeout"] = int(argument)
            except ValueError:
                logging.critical("--timeout|-t parameter must be an integer value")
                sys.exit(1)
            if parameters["Timeout"] < 1:
                logging.critical("--timeout|-t parameter must be a strictly positive value")
                sys.exit(1)
            if parameters["Timeout"] < 10:
                logging.warning("--timeout|-t parameter value is rather short")

    logging.debug("_process_command_line(): parameters:")
    logging.debug(parameters)
    logging.debug("_process_command_line(): remaining_arguments:")
    logging.debug(remaining_arguments)

    return remaining_arguments


####################################################################################################
def main():
    """ The program's main entry point """
    program_name = os.path.basename(sys.argv[0])

    libpnu.initialize_debugging(program_name)
    libpnu.handle_interrupt_signals(libpnu.interrupt_handler_function)
    _process_environment_variables()
    arguments = _process_command_line()

    exit_status = 0
    if arguments:
        for argument in arguments:
            try:
                lines = read_input_file(argument)
            except FileNotFoundError:
                logging.error("filename '%s' not found", argument)
                exit_status = 1
                continue

            # Remove commented and empty lines
            input_data = get_input_data(lines)

            certs, errors = get_certs(
                input_data,
                progress_bar = parameters["Show progress"],
                timeout = parameters["Timeout"],
                save_cert_dir = parameters["Save cert dir"],
                delay = parameters["Delay"],
            )

            print_table(
                certs,
                errors,
                show_alt_names = parameters["Show alt names"],
                show_ip = parameters["Show IP address"],
                expiration = parameters["Expiration days"],
            )

            if parameters["Excel filename"]:
                generate_excel(
                    parameters["Excel filename"],
                    certs,
                    errors,
                    expiration = parameters["Expiration days"],
                )

            if parameters["Show new names"]:
                new_cn, new_an = get_new_names(certs, errors)

                print_new_names(new_cn, new_an)
                if parameters["Excel filename"]:
                    update_excel(
                        parameters["Excel filename"],
                        new_cn,
                        new_an,
                    )

    else:
        _display_help()

    sys.exit(exit_status)


if __name__ == "__main__":
    main()
