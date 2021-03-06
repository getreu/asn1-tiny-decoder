"""Analyse a CRL (certifcate revocation list), store pointers in a
dictionary and print out the content of a CRL
This code illustrates the usage of asn1decoder
"""

################## BEGIN ASN1 DECODER USAGE EXAMPLE  ###################

# Author: Jens Getreu, 8.11.2014, Version 1.0
# Please install also dumpasn1 package with you package manager!

from datetime import datetime
from typing import Tuple, Dict
from subprocess import Popen, PIPE, STDOUT  # for debugging only

from asn1tinydecoder import (
    asn1_node_root,
    asn1_get_all,
    asn1_get_value,
    asn1_get_value_of_type,
    asn1_node_next,
    asn1_node_first_child,
    asn1_read_length,
    asn1_node_is_child_of,
    bytestr_to_int,
)


def dump_asn1(der: bytes) -> str:
    """
    Install dumpasn1 package to make this work.
    For debugging only, prints ASN1 structures nicely.
    """
    p = Popen(["dumpasn1", "-a", "-"], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    dump = p.communicate(input=der)[0]
    return dump.decode()


def extract_crl_info(crl_der: bytes) -> Tuple[datetime, datetime, bytes, Tuple[int, int, int], Dict[int, Tuple[int, int, int]]]:
    """
    This function extracts some header fields of the CRL list
    and stores pointers to the list entries in a dictionary
    """
    # unpack sequence
    i = asn1_node_root(crl_der)
    # unpack sequence
    i = asn1_node_first_child(crl_der, i)
    crl_signed_content = i

    # get 1. item inside (version)
    i = asn1_node_first_child(crl_der, i)
    # advance 1 item (Algoidentifier)
    i = asn1_node_next(crl_der, i)
    # advance 1 item (email, CN etc.)
    i = asn1_node_next(crl_der, i)
    # advance 1 item
    i = asn1_node_next(crl_der, i)
    bytestr = asn1_get_value_of_type(crl_der, i, "UTCTime")
    crl_not_valid_before = datetime.strptime(bytestr.decode("utf8"), "%y%m%d%H%M%SZ")
    # advance 1 item
    i = asn1_node_next(crl_der, i)
    bytestr = asn1_get_value_of_type(crl_der, i, "UTCTime")
    crl_not_valid_after = datetime.strptime(bytestr.decode("utf8"), "%y%m%d%H%M%SZ")

    # advance 1 item (the list)
    i = asn1_node_next(crl_der, i)

    # Stores for every certificate entry the serial number and and
    # 3 pointers indication the position of the certificate entry.
    # Returns a dictionary.
    # key = certificate serial number
    # value = 3 pointers to certificate entry in CRL

    # open and read 1. item
    j = asn1_node_first_child(crl_der, i)
    serials_idx = {}

    while asn1_node_is_child_of(i, j):
        # read 1. interger inside item
        k = asn1_node_first_child(crl_der, j)
        serial = bytestr_to_int(asn1_get_value_of_type(crl_der, k, "INTEGER"))
        # store serial and the asn1 container position
        serials_idx[serial] = j

        # point on next item in the list
        j = asn1_node_next(crl_der, j)

    # advance 1 item
    i = asn1_node_next(crl_der, i)
    # advance 1 item (obj. identifier)
    i = asn1_node_next(crl_der, i)
    # advance 1 item (signature)
    i = asn1_node_next(crl_der, i)
    # content is crl_signature
    crl_signature = asn1_get_value_of_type(crl_der, i, "BIT STRING")
    if crl_signature[0] != 0x00:
        raise ValueError("Error: CRL signature should start with 0x00 padding!")
    crl_signature = crl_signature[1:]

    return (
        crl_not_valid_before,
        crl_not_valid_after,
        crl_signature,
        crl_signed_content,
        serials_idx,
    )


def search_certificate(
    crl_der: bytes,
    serial: int,
    dictionary: Tuple[
        datetime, datetime, bytes, Tuple[int, int, int], Dict[int, Tuple[int, int, int]]
    ],
) -> None:
    """Print the header fields and the dictionary"""
    a, b, c, d, serials_idx = dictionary
    print("*** Some information about the CRL")
    print("crl_not_valid_before: ", a)
    print("crl_not_valid_after:  ", b)
    print("crl_signature:        ", c.hex()[:30], "... ", len(c), " Bytes")
    ixs, ixf, ixl = d
    print("crl_signed_content:   ", d, ixl + 1 - ixs, "Bytes")
    # print(dump_asn1(asn1_get_all(crl_der, d)))
    print()
    print("*** The CRL lists", len(serials_idx), "certificates.")
    if len(serials_idx) <= 10:
        for s, p in serials_idx.items():
            print("serial: ", s, "  position:", p)
    print()

    print("*** Search in CRL for serial no:", serial)
    print()

    if serial in serials_idx:
        print("*** SERIAL FOUND IN LIST!:")
        print("**      Revoked certificate data")
        print("- Certificate serial no: ", serial)
        # Now use the pointers to print the certificate entries.
        print("- Decoded ASN1 data:")
        p = serials_idx[serial]
        print(dump_asn1(asn1_get_all(crl_der, p)))
        print()


def main():
    """Main program"""
    crl_filename = "www.sk.ee-crl.crl"
    search_serial = 1018438612

    print("****** INDEXING CRL:", crl_filename)
    print()
    crl_der = open(crl_filename, "rb").read()
    dictionary = extract_crl_info(crl_der)
    search_certificate(crl_der, search_serial, dictionary)
    # print(dump_asn1(crl_der))
    print()
    print()

    crl_filename = "www.sk.ee-esteid2011.crl"
    search_serial = 131917818486436565990004418739006228479

    print("****** INDEXING CRL:", crl_filename)
    print()
    crl_der = open(crl_filename, "rb").read()
    dictionary = extract_crl_info(crl_der)
    search_certificate(crl_der, search_serial, dictionary)


if __name__ == "__main__":
    main()


################## END DECODER USAGE EXAMPLE  ######################
