= Tiny and fast ASN.1 decoder in Python
Jens Getreu
v1.0, 8.11.2014
:icons: font
:numbered:
:toc:
:pagenums:
//:source-highlighter: coderay

link:data/asn1tinydecoder.py[`asn1tinydecoder.py`]
```asn1tinydecoder.py`` <data/asn1tinydecoder.py>`__ is a simple and
fast ASN.1 decoder without external libraries designed to parse large
files.

A widely used library for encoding and decoding ASN1 in python is
`Pyasn1 <http://pyasn1.sourceforge.net/>`__. The implementation covers
many aspects of ASN1, but the API is very complex and hard to learn.
Furthermore Pyasn1 is not designed to parse large files. This why I
wrote this tiny ASN.1 decoder. It’s design goal was to be as fast as
possible (with Python 2).  [1]_

A practical application can be found in
`??? <#Search serial in large certificate revocation lists>`__: This
program creates an index allowing fast search in big ASN.1 data
structures.

The source code is hosted on
`Github <https://github.com/getreu/asn1-tiny-decoder>`__.

.. [1]
   Python 3 would have been a better choice for ``asn1tinedecoder``
   because of its ``bytes`` type. Any volunteer to port to Python 3?
