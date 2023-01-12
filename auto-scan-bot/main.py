#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Auto Scan Bot")
        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getUrl() == newIssue.getUrl() and
                existingIssue.getIssueName() == newIssue.getIssueName()):
            return -1
        else:
            return 0

    def scan(self, baseRequestResponse, insertionPoint):
        print("Scanning...")
        # Perform active scan on site
        issues = self._callbacks.doActiveScan(baseRequestResponse.getUrl().toString(), baseRequestResponse)
        return issues

    
################################
#         Bot Details
# BurpSuiteBots/auto-scan-bott/main.py 
# Version: 1.0
################################
#         Copyright Details
# © OpenBotBook
# https://github.com/OpenBotBook
# Apache License
# Version 2.0, January 2004
# http://www.apache.org/licenses/
################################
