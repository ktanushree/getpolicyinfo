# Prisma SDWAN Get Policy Info
This utility is used to download details about Prisma SDWAN policies and the rules.

#### Synopsis
This script can be used to understand all the policies (Security, Path, QoS & NAT) and the corresponding rule definition. 
It downloads the policy details in a CSV.

#### Note Version 1 only supports retrieval of Security Policies.

#### Requirements
* Active Prisma SDWAN Account
* Python >=3.6
* Python modules:
    * Prisma SDWAN (CloudGenix) Python SDK >= 5.5.3b1 - <https://github.com/CloudGenix/sdk-python>

#### License
MIT

#### Installation:
 - **Github:** Download files to a local directory, manually run `getpolicyinfo.py`. 

### Examples of usage:

```
./getpolicyinfo.py
```


Help Text:
```angular2
TanushreeKamath:getpolicyinfo tkamath$ ./getpolicyinfo.py -h
usage: getpolicyinfo.py [-h] [--controller CONTROLLER] [--email EMAIL] [--pass PASS]

Prisma SDWAN: Get Policy Info.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod: https://api.elcapitan.cloudgenix.com

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of prompting
  --pass PASS, -P PASS  Use this Password instead of prompting
TanushreeKamath:getpolicyinfo tkamath$ 
```

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b2** | Retrieves IP prefixes & zone mapping in separate CSVs|
|           | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SDWAN Documentation at <https://docs.paloaltonetworks.com/prisma/prisma-sd-wan.html>
