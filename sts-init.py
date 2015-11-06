#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import commands
import boto.sts
import boto.s3
import requests
import getpass
import ConfigParser
import base64
import xml.etree.ElementTree as ET
import requests
import krbV
from requests_kerberos import HTTPKerberosAuth, OPTIONAL
from bs4 import BeautifulSoup
from os.path import expanduser
from urlparse import urlparse, urlunparse
from requests_ntlm import HttpNtlmAuth


##########################################################################
# Variables

# region: The default AWS region that this script will connect
# to for all API calls
region = 'us-east-1'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# awsconfigfile: The file where this script will store the temp
# credentials under the saml profile
awsconfigfile = '/.aws/credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True

# idpentryurl: The initial URL that starts the authentication process.
idpentryurl = 'https://adfs.commercehub.com/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'

def has_ticket():
    '''
    Checks to see if the user has a valid ticket.
    '''
    ctx = krbV.default_context()
    cc = ctx.default_ccache()
    try:
        princ = cc.principal()
        retval = True
    except krbV.Krb5Error:
        retval = False

    return retval

def do_kinit():
    # Get the federated credentials from the user
    kinit = 'kinit'
    print "Enter Your Password"
    return_var = commands.getstatusoutput(kinit)
    return return_var

def handle_sts_by_ntlm():
    # Initiate session handler
    session = requests.Session()

    print "Username as <domain>\<username>:",
    username = raw_input()
    password = getpass.getpass()
    print ''
    session.auth = HttpNtlmAuth(username, password, session)
    # Programatically get the SAML assertion
    headers = {'User-Agent': 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}
    response = session.get(idpentryurl, verify=sslverification, headers=headers)

    handle_sts_from_response(response)

def handle_sts_by_kerberos():
    # Initiate session handler
    session = requests.Session()
    # Programatically get the SAML assertion
    headers = {'User-Agent': 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}
    response = session.get(idpentryurl, verify=sslverification, headers=headers, auth=HTTPKerberosAuth(mutual_authentication=OPTIONAL))
    handle_sts_from_response(response)


def handle_sts_from_response(response):
    soup = BeautifulSoup(response.text.decode('utf8'), "html.parser")
    assertion = ''

    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            #print(inputtag.get('value'))
            assertion = inputtag.get('value')

    # Parse the returned assertion and extract the authorized roles
    awsroles = []
    root = ET.fromstring(base64.b64decode(assertion))

    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                awsroles.append(saml2attributevalue.text)

    # Note the format of the attribute value should be role_arn,principal_arn
    # but lots of blogs list it as principal_arn,role_arn so let's reverse
    # them if needed
    for awsrole in awsroles:
        chunks = awsrole.split(',')
        if'saml-provider' in chunks[0]:
            newawsrole = chunks[1] + ',' + chunks[0]
            index = awsroles.index(awsrole)
            awsroles.insert(index, newawsrole)
            awsroles.remove(awsrole)

    # If I have more than one role, ask the user which one they want,
    # otherwise just proceed
    print ""
    if len(awsroles) > 1:
        i = 0
        print "NOTE: You have multiple roles - a profile will be created for each"
        expires_utc = 0
        for awsrole in awsroles:
            profile ='saml-'+ str(i)
            print '[', profile, ']: ', awsrole.split(',')[0]
            expires_utc = bind_assertion_to_role(assertion, awsrole, profile).credentials.expiration
            i += 1
        print '\n\n----------------------------------------------------------------'
        print 'Your new access key pairs have been stored in the AWS configuration file {0} under the saml-<i> profiles.'.format(expanduser("~") + awsconfigfile)
        print 'Note they will expire at {0}.'.format(expires_utc)
        print 'After this time you may safely rerun this script to refresh your access key pair.'
        print 'To use this credential call the AWS CLI with the --profile option (e.g. aws --profile saml-0 ec2 describe-instances).'
        print '----------------------------------------------------------------\n\n'

    else:
        bind_assertion_to_role(assertion, awsroles[0], 'saml')
        print '\n\n----------------------------------------------------------------'
        print 'Your new access key pair has been stored in the AWS configuration file {0} under the saml profile.'.format(expanduser("~") + awsconfigfile)
        print 'Note that it will expire in 1 hour'
        print 'After this time you may safely rerun this script to refresh your access key pair.'
        print 'To use this credential call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).'
        print '----------------------------------------------------------------\n\n'


def bind_assertion_to_role(assertion, role, profile):
    conn = boto.sts.connect_to_region(region)
    role_arn = role.split(',')[0]
    principal_arn = role.split(',')[1]
    token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)
    # Write the AWS STS token into the AWS credential file
    home = expanduser("~")
    filename = home + awsconfigfile

    # Read in the existing config file
    config = ConfigParser.RawConfigParser()
    config.read(filename)

    # Put the credentials into a specific profile instead of clobbering
    # the default credentials
    if not config.has_section(profile):
        config.add_section(profile)

    config.set(profile, 'output', outputformat)
    config.set(profile, 'region', region)
    # Just makes it easier to tell them appart when looking in the file
    config.set(profile, 'aws_role_arn', role_arn)
    config.set(profile, 'aws_access_key_id', token.credentials.access_key)
    config.set(profile, 'aws_secret_access_key', token.credentials.secret_key)
    config.set(profile, 'aws_session_token', token.credentials.session_token)

    # Write the updated config file
    with open(filename, 'w+') as configfile:
        config.write(configfile)
    return token

##########################################################################
def main():
    # Get the federated credentials from the user
    hasTicket = has_ticket()
    if hasTicket == True:
        print "It looks like you have a valid Windows/Kerberos Session. This should 'Just Work™'."
        handle_sts_by_kerberos()
    else:
        print "No valid Kerberos Token/Cache found. Ahhh 💩"
        print "Maybe we can create one... hang on"
        kinit_result = do_kinit()
        if kinit_result[0] == 0:
            handle_sts_by_kerberos()
        else:
            print kinit_result[1]
            print "Ehh, sorry but that still didn't work. Bear with me while we go old school. 🚌"
            try:
                handle_sts_by_ntlm()
            except:
                print "All hope is lost. I hope your problem is something simple like being off network, but I don't know 😕"
                raise
main()
