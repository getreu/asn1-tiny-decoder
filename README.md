---
title: Tiny and fast ASN.1 decoder in Python 
author: Jens Getreu 
---

[asn1tinydecoder.py](./source/data/asn1tinydecoder.py) is a simple and fast ASN.1 decoder
without external libraries designed to parse large files.

A widely used library for encoding and decoding ASN1 in python is
[Pyasn1](http://pyasn1.sourceforge.net/). The implementation covers many aspects
of ASN1, but the API is very complex and hard to learn.  Furthermore Pyasn1 is
not designed to parse large files. This why I wrote this tiny ASN.1 decoder.
It's design goal was to be as fast as possible.

A practical application can be found in
[search_serial_in_large_CRL.py](./source/data/search_serial_in_large_CRL.py):
This show case program creates an index allowing fast search in big ASN.1 data
structures.

The source code is hosted on
[Gitlab](https://gitlab.com/getreu/asn1-tiny-decoder).
