#!/usr/bin/python

import smtplib

sender = 'prez@whitehouse.com'
receivers = ['mary@rosehowell.com']

message = """From: theprez <prez@whitehouse.com>
To: Mary <mary@rosehowell.com>
Subject: SMTP e-mail test

This is a test e-mail message.
"""

try:
   smtpObj = smtplib.SMTP('localhost')
   print "dir of smtpObj: {}".format(dir(smtpObj))
   smtpObj.sendmail(sender, receivers, message)         
   print "Successfully sent email"
except smtplib.SMTPException:
   print "Error: unable to send email"