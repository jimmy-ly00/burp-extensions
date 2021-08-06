from burp import IBurpExtender
"""
Name:           External Crypto Header
Version:        0.0.1
Date:           10/03/2021
Author:         Jimmy Ly
Github:         https://github.com/jimmy-ly00

Description:    This plugin adds headers useful for XXX
"""

from burp import ISessionHandlingAction
from burp import IParameter
from java.io import PrintWriter
import hashlib

import time
import subprocess
import urlparse

class BurpExtender(IBurpExtender, ISessionHandlingAction):
  def current_milli_time(self):
    return str(int(time.time() * 1000))

  def run_external(self, payload):
    # https://github.com/externalist/aes-encrypt-decrypt-burp-extender-plugin-example
    proc = subprocess.Popen(['python','./sign.py', self.key, payload],stdout=subprocess.PIPE)
    output = proc.stdout.read().strip()
    proc.stdout.close()
    return output

  def registerExtenderCallbacks(self, callbacks):
    # stdout = PrintWriter(callbacks.getStdout(), True)
    # stderr = PrintWriter(callbacks.getStderr(), True)
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()
    callbacks.setExtensionName("Custom External Crypto Headers")
    callbacks.registerSessionHandlingAction(self)

    return

  def getActionName(self):
    return "Custom External Crypto Headers"

  def performAction(self, currentRequest, macroItems):
    requestInfo = self._helpers.analyzeRequest(currentRequest)
    headers = requestInfo.getHeaders()
    newHeaders = list(headers)

    reqBody = currentRequest.getRequest()[requestInfo.getBodyOffset():]
    body_parameters = self._helpers.bytesToString(reqBody)

    api_key = "XXX"
    timestamp = self.current_milli_time()
    content_md5 = ""
    content_type = ""
    api_endpoint = urlparse.urlparse(str(currentRequest.getUrl())).path

    # Get parameters in URL (for some reason POST data would be included, so we specify for only GET)
    for header in newHeaders:
      if (header.lower().startswith("get")):
        get_parameters = sorted(requestInfo.getParameters())

        # Some hack way to get parameters and sort e.g. https://domain.com/?a=first&c=third&b=second will give a=first&b=second&c=third
        # a lot of weird edge cases
        if get_parameters:
          temp=[]
          for parameter in get_parameters:
            temp.append(parameter.getName() + '=' + parameter.getValue() + '&')
          api_parameters = (''.join(sorted(temp))[:-1])
          api_endpoint = api_endpoint + '?' + api_parameters

    # Remove old HTTP headers
    for header in newHeaders:
      if (header.lower().startswith("content-type")):
        headers.remove(header)
      if (header.lower().startswith("x-signature")):
        headers.remove(header)
      if (header.lower().startswith("x-apikey")):
        headers.remove(header)
      if (header.lower().startswith("x-timestamp")):
        headers.remove(header)
      if (header.lower().startswith("content-md5")):
        headers.remove(header)

    # Hacky method (no regex) to check if GET or POST/PUT HTTP method e.g. if headers has GETTEST it will be a valid GET too
    for header in newHeaders:
      if (header.lower().startswith("get")):
        # headers.add('Content-Type: text/plain')
        StringToSign = "GET" + "\n" + timestamp + "\n" + content_md5 + "\n"+ content_type + "\n" + api_key + "\n" + api_endpoint
      if (header.lower().startswith("post")):
        content_type = 'application/json'
        headers.add('Content-Type: ' + content_type)
        content_md5 = hashlib.md5(body_parameters).hexdigest()
        headers.add('Content-MD5: ' + content_md5)
        StringToSign = "POST" + "\n" + timestamp + "\n" + content_md5 + "\n"+ content_type + "\n" + api_key + "\n" + api_endpoint
      if (header.lower().startswith("put")):
        content_type = 'application/json'
        headers.add('Content-Type: ' + content_type)
        content_md5 = hashlib.md5(body_parameters).hexdigest()
        headers.add('Content-MD5: ' + content_md5)
        StringToSign = "PUT" + "\n" + timestamp + "\n" + content_md5 + "\n"+ content_type + "\n" + api_key + "\n" + api_endpoint

    # headers.add(StringToSign)
    # Call external program to run python program. Uses locally installed pycryptodome cryptographic signing functions
    proc = subprocess.Popen(['py',"./sign.py", StringToSign],stdout=subprocess.PIPE)
    output = proc.stdout.read().strip()
    proc.stdout.close()

    headers.add("X-Signature: " + output)
    headers.add("X-Timestamp: " + timestamp)
    headers.add("X-APIkey: " + api_key)

    # Build request with new headers
    message = self._helpers.buildHttpMessage(headers, reqBody)

    # Update Request with new headers
    currentRequest.setRequest(message)
    return
