# Burp Extensions
A collection of burp extensions that may be useful for others. These are required to be cleaned and tested, and will contain bugs!

## Instructions
1. Add via Extender > Add > Extension Type: Python 
2. Project Options > Sessions > Under 'Session Handling Rules' > Add  > Under 'Rule Actions' > Add > Invoke a Burp Extension > Select 'burp-external-crypto-header.py'. Ensure 'Tool Scope' and 'URL Scope' has been specified.

## Tools
### burp-external-crypto-header
Adds custom headers, one which requires using cryptographic signing (RSA). To overcome Jython limitations, it calls an extenal program to perform cryptographic functions using python subprocess and crypto packages. It then returns the output to the Burp extension to be processed and added as a HTTP header.

Jython has issues calling cryptographic libraries, or in fact any built-in library written in C, see the following link: https://www.jython.org/jython-old-sites/docs/library/indexprogress.html. We also cannot use packages such as pycryptodome that needs to be pip installed. There are three ways to overcome this:

1. Use Python subprocess to tell your extension to run an external (python) program which removes the limitation as it runs on your local python now.
2. Import and use Java functions in Python: https://parsiya.net/blog/2018-12-24-cryptography-in-python-burp-extensions/#aes-cfb-nopadding.
3. Create the extension on Java instead.

This extension uses method 1. The main drawback would be I/O limitations as it uses subprocesses.

### burp-hash-header
Uses hashlib to add a custom header which is a hash of the header and parameters
