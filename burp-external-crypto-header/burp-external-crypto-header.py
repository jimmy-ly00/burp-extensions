from burp import IBurpExtender
"""
Name:           External Crypto Header
Version:        0.0.1
Date:           27/04/2021
Author:         Jimmy Ly
Github:         https://github.com/jimmy-ly00

Description:    This plugin adds headers useful for XXX
                To run cryptographic functions and overcome Jython issues with calling built-in C 
                libraries (e.g. Crypto). It calls an external (Python) program which removes the 
                limitation of requiring built-in C libraries and pip installed tools.
"""

from burp import ISessionHandlingAction
from burp import IParameter
from java.io import PrintWriter

import time
import subprocess

class BurpExtender(IBurpExtender, ISessionHandlingAction):
  def current_milli_time(self):
    return str(int(time.time() * 1000))

  def run_external(self, payload):
    # https://github.com/externalist/aes-encrypt-decrypt-burp-extender-plugin-example
    proc = subprocess.Popen(['python','./encrypt.py', self.key, payload],stdout=subprocess.PIPE)
    output = proc.stdout.read().strip()
    proc.stdout.close()
    return output

  def registerExtenderCallbacks(self, callbacks):
    # stdout = PrintWriter(callbacks.getStdout(), True)
    # stderr = PrintWriter(callbacks.getStderr(), True)
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()
    callbacks.setExtensionName("External Crypto Header")
    callbacks.registerSessionHandlingAction(self)

    return

  def getActionName(self):
    return "External Crypto Header"

  def performAction(self, currentRequest, macroItems):
    requestInfo = self._helpers.analyzeRequest(currentRequest)
    headers = requestInfo.getHeaders()
    newHeaders = list(headers)

    reqBody = currentRequest.getRequest()[requestInfo.getBodyOffset():]
    # parameters = self._helpers.bytesToString(reqBody)

    C1_key = "API_KEY"
    timestamp = self.current_milli_time()
    ContentMD5 = ""
    ContentType = ""
    api_endpoint = "/api/v2/endpoint"
    StringToSign1 = "GET" + "\n" + timestamp + "\n" + ContentMD5 + "\n"+ ContentType + "\n" + C1_key + "\n" + api_endpoint

    # Remove old HTTP headers
    for header in newHeaders:
      if (header.startswith("Content-Type")):
        headers.remove(header)
      if (header.startswith("X-Signature")):
        headers.remove(header)
      if (header.startswith("X-APIkey")):
        headers.remove(header)
      if (header.startswith("X-Timestamp")):
        headers.remove(header)

    # Hacky method (no regex) to check if GET or POST/PUT HTTP method e.g. if headers has GETTEST it will be a valid GET too
    for header in newHeaders:
      if (header.startswith("GET")):
        headers.add('Content-Type: text/plain')
      if (header.startswith("POST")) or (header.startswith("PUT")):
        headers.add('Content-Type: application/json')

    # Call external program to run python program. Uses locally installed pycryptodome cryptographic signing functions
    proc = subprocess.Popen(['py',"./sign.py", StringToSign1],stdout=subprocess.PIPE) # Modify this line for your python instance, e.g. py sign.py anystring or python3 sign.py anystring
    output = proc.stdout.read().strip()
    proc.stdout.close()

    headers.add("X-Timestamp: " + timestamp)
    headers.add("X-Signature: " + output)
    headers.add("X-APIkey: " + C1_key)

    # Build request with new headers
    message = self._helpers.buildHttpMessage(headers, reqBody)

    # Update Request with new headers
    currentRequest.setRequest(message)
    return
