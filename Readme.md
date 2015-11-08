# AWS CLI Kerberos Adapter

## Overview
This script provides a seamless mechanism for federating the AWS CLI. When
properly configured this script allows a user to get a short lived set of
credentials for each authorized role.

The script leverages Kerberos and ADFS to avoid any need for the user to enter
a AD domain password or provide AWS credentials. The script gracefully degrades
as follows
* If there is no current kerberos cache, the user is prompted for a password
* If kerberos is not available the user is prompted for a username, password pair

This script does not work if the user of not on a corporate network or VPN.
It would be highly desirable to support off network access via a SecurID prompt
when required.


## Installation
*This script has not been tested onLinux*

### OSX
0. Install python - The script has been tested with the default instal of 2.7 on OSX
1. Install pip - $ sudo easy_install pip
2. Install required packages - $ sudo -H pip install -U boto beautifulsoup4 requests-ntlm requests-ntlm requests-kerberos
3. Install aws cli -  $ sudo -H pip install -U awscli
5. Update ~/.bash_profile - $ echo 'export PYTHONPATH="/Library/Python/2.7/site-packages:$PYTHONPATH"' >> ~/.bash_profile && source ~/.bash_profile
6. Add to your search $PATH - $ ln -s ./sts-init.py /usr/local/bin/sts-init

### Windows
0. Install python - Tested with 2.7.x. Not tested with 3.x but feel free to try it.
1. Ensure python and python/scripts are on the PATH
2. Install required packages - pip install -U boto beautifulsoup4 requests-ntlm requests-ntlm
3. Install requests-kerberos from this repo - cd to requests-kerberos and type 'pip install --replace'
4. Install the aws cli - You need the MSI directly from amazon
