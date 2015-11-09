# AWS CLI Kerberos Adapter

Based on the ADSF-CLI script  [originally posted by Quint Van Deman] (https://blogs.aws.amazon.com/security/post/Tx1LDN0UBGJJ26Q/How-to-Implement-Federated-API-and-CLI-Access-Using-SAML-2-0-and-AD-FS)
## Overview
This script provides a seamless mechanism for federating the AWS CLI. When
properly configured this script allows a user to get a short lived set of
credentials for each authorized role.

The script leverages Kerberos and ADFS to avoid any need for the user to enter
a AD domain password or provide AWS credentials. The script gracefully degrades
as follows
* If kerberod auth fails, we fallback to NTLM username/password prompt
* The user may opt to Ctrl-C the script and initialized a kerberos session instead

This script does not work if the user is not on a corporate network or VPN.
It would be highly desirable to support off network access via a SecurID prompt
when required.

## Installation
* *Note: This script has not been tested on Linux*
* *Note: Python 2.7.10 is the minimal version supported*
* *Note: This script has only been tested on Windows 7 and OSX Yosemite*

### OSX
0. Install python - The script has been tested with the default instal of 2.7 on OSX
1. Install pip - $ sudo easy_install pip
2. Install required packages - $ sudo -H pip install -U boto beautifulsoup4 requests-ntlm requests-kerberos
3. Install aws cli -  $ sudo -H pip install -U awscli
5. Update ~/.bash_profile - $ echo 'export PYTHONPATH="/Library/Python/2.7/site-packages:$PYTHONPATH"' >> ~/.bash_profile && source ~/.bash_profile
6. Add to your search $PATH - $ ln -s ./sts-init.py /usr/local/bin/sts-init

### Windows
*The currently released version (0.7) of requests-kerberos does not correctly support Win32.
This repo includes a recently merged changeset which includes the [necessary fix] (https://github.com/requests/requests-kerberos/commit/27e5d006d9e8182b05e9e366301a7fc890529113).*

0. Install python - Tested with 2.7.x. Not tested with 3.x but feel free to try it.
1. Ensure python and python/scripts are on the PATH
2. Install required packages - pip install -U boto beautifulsoup4 requests-ntlm requests-ntlm
3. Install requests-kerberos from this repo - cd to requests-kerberos and type 'pip install --replace'
4. Install the aws cli - You need the MSI directly from amazon

## Usage
#### OSX
```
  $ sts-init
```

#### Windows
```
  C\:> python /location/of/script/sts-init.py
```

## Configuration

The script attempts to create default configurations if none are found.

### Credential File
The AWS default location for the credential file is ~/.aws. For this script to work there
must be a minimal file in place. The script attempts to creste this file at start
up. If an existing file is malformed, please remove it.

### Localsite file
This script creats an additional configuration file, ~/.aws/localsite. This file
contains any custom configurations such as the location of the ADFS server. At
startup you will be asked for the domain of the adfs server. There is no validation
of the input value and you will not be prompted again to provide a value. Remove
this file if you need to be prompted again for a new value.
