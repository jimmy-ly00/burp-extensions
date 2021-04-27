from burp import IBurpExtender
"""
Name:           Digest Hash Header
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

class BurpExtender(IBurpExtender, ISessionHandlingAction):

  def registerExtenderCallbacks(self, callbacks):
    # stdout = PrintWriter(callbacks.getStdout(), True)
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()
    callbacks.setExtensionName("Custom Digest Hash Header")
    callbacks.registerSessionHandlingAction(self)
    return

  def getActionName(self):
    return "Custom Digest Hash Header"

  def performAction(self, currentRequest, macroItems):
    requestInfo = self._helpers.analyzeRequest(currentRequest)
    headers = requestInfo.getHeaders()
    newHeaders = list(headers) 

    reqBody = currentRequest.getRequest()[requestInfo.getBodyOffset():]

    # Items to hash
    bearer_token = ""
    parameters = self._helpers.bytesToString(reqBody)

    # Remove old digest header and get Authorization Bearer from HTTP headers
    for header in newHeaders:
      if (header.startswith("Digest")):
        headers.remove(header)
      if (header.startswith("Authorization")):
        bearer_token = header.split("Bearer ",1)[1]

    headers.add('Digest: ' + hashlib.sha256(bearer_token + parameters).hexdigest())

    # Build request with bypass headers
    message = self._helpers.buildHttpMessage(headers, reqBody)

    # Update Request with New Header
    currentRequest.setRequest(message)
    return 