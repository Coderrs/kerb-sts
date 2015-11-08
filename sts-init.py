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
import os.path
from requests_kerberos import HTTPKerberosAuth, OPTIONAL
from bs4 import BeautifulSoup
from os.path import expanduser
from urlparse import urlparse, urlunparse
from requests_ntlm import HttpNtlmAuth


##########################################################################
# Variables
config_filename = ''
site_config_filename = ''
idpentryurl = ''
# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True




def do_kinit():
    print "WARN: There was no Kerberos cache or ticket available."
    print "WARN: Try running 'kinit' before running this script again"
    print "WARN: Hit Ctrl-c if you want to try kinit now"

def handle_sts_by_ntlm():
    session = requests.Session()
    print "Username as <domain>\<username>:",
    username = raw_input()
    password = getpass.getpass()
    print ''
    session.auth = HttpNtlmAuth(username, password, session)
    # A hack added for ADFS 3.0
    headers = {'User-Agent': 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}
    response = session.get(idpentryurl, verify=sslverification, headers=headers)

    handle_sts_from_response(response)

def handle_sts_by_kerberos():

    session = requests.Session()
    # A hack added for ADFS 3.0
    headers = {'User-Agent': 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}
    response = session.get(idpentryurl, verify=sslverification, headers=headers, auth=HTTPKerberosAuth(mutual_authentication=OPTIONAL))
    if response.status_code == requests.codes.ok:
        handle_sts_from_response(response)
    else:
        do_kinit()
        handle_sts_by_ntlm()

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
    #print '>'+assertion+'<'
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
        print '----------------------------------------------------------------'
        print 'Your new access key pairs have been stored in the AWS configuration'
        print 'file {0} under the saml-<i> profiles.'.format(config_filename)
        print 'Note they will expire at {0}.'.format(expires_utc)
        print 'After this time you may safely rerun this script to refresh your access key pair.'
        print 'To use this credential call the AWS CLI with the --profile option'
        print 'e.g. aws --profile saml-0 ec2 describe-instances.'
        print '----------------------------------------------------------------'

    else:
        bind_assertion_to_role(assertion, awsroles[0], 'saml')
        print '----------------------------------------------------------------'
        print 'Your new access key pair has been stored in the AWS configuration '
        print 'file {0} under the saml profile.'.format(expanduser("~") + config_filename)
        print 'Note that it will expire in 1 hour'
        print 'After this time you may safely rerun this script to refresh your access key pair.'
        print 'To use this credential call the AWS CLI with the --profile option '
        print 'e.g. aws --profile saml-0 ec2 describe-instances.'
        print '----------------------------------------------------------------'


def bind_assertion_to_role(assertion, role, profile):

    config = ConfigParser.RawConfigParser()
    config.read(config_filename)
    region = config.get('default','region')
    conn = boto.sts.connect_to_region(region)
    role_arn = role.split(',')[0]
    principal_arn = role.split(',')[1]
    token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)
    # Write the AWS STS token into the AWS credential file
    # Read in the existing config file
    config = ConfigParser.RawConfigParser()
    config.read(config_filename)

    # Put the credentials into a specific profile instead of clobbering
    # the default credentials
    if not config.has_section(profile):
        config.add_section(profile)

    config.set(profile, 'output', outputformat)
    #config.set(profile, 'region', region)
    # Just makes it easier to tell them appart when looking in the file
    config.set(profile, 'aws_role_arn', role_arn)
    config.set(profile, 'aws_access_key_id', token.credentials.access_key)
    config.set(profile, 'aws_secret_access_key', token.credentials.secret_key)
    config.set(profile, 'aws_session_token', token.credentials.session_token)
    config.set(profile, 'aws_session_expires_utc', token.credentials.expiration)

    # Write the updated config file
    with open(config_filename, 'w+') as configfile:
        config.write(configfile)
    return token

def verify_default_credential_file(filename):
    if not os.path.isfile(filename):
        if not(os.path.exists(os.path.dirname(filename))):
            os.makedirs(os.path.dirname(filename))
        with open(filename, 'a') as the_file:
            the_file.write('[default]\n')
        config = ConfigParser.RawConfigParser()
        config.read(filename)
        #if not config.has_section('default'):
        config.set('default', 'output', 'json')
        config.set('default', 'region', 'us-east-1')
        config.set('default', 'aws_access_key_id', '')
        config.set('default', 'aws_secret_access_key', '')
        with open(filename, 'w+') as configfile:
            config.write(configfile)
        print "New credential file created - " + filename

def verify_local_site_file(filename):
    if not os.path.isfile(filename):
        if not(os.path.exists(os.path.dirname(filename))):
            os.makedirs(os.path.dirname(filename))
        with open(filename, 'a') as the_file:
            the_file.write('[default]\n')

        print "INTIAL CONFIGURATION NEEDED",
        print "Please enter the domain name of your ADFS server [adfs.yoursite.com]",
        adfs_domain = raw_input()
        config = ConfigParser.RawConfigParser()
        config.read(filename)

        config.set('default', 'idp_url', 'https://'+adfs_domain+'/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices')
        with open(filename, 'w+') as configfile:
            config.write(configfile)
        print "New site configuration file created - " + filename

    site_config = ConfigParser.RawConfigParser()
    site_config.read(filename)

    global idpentryurl
    idpentryurl = site_config.get('default', 'idp_url')


def verify_defaults():
    awsconfigfile = '/.aws/credentials'
    home = expanduser("~")
    filename = home + awsconfigfile
    verify_default_credential_file(filename)
    site_filename = home + '/.aws/localsite'
    verify_local_site_file(site_filename)

    global config_filename
    config_filename = filename
    global site_config_filename
    site_config_filename = site_filename


##########################################################################
def main():
    verify_defaults()
    try:
        handle_sts_by_kerberos()
    except:
        print "Something unexpected happened. Maybe you are off network?"
        raise
main()
