# VulnCheckTools
 Various Tools for VulnCheck API

This is a simply Python based wrapper for the VulnCheck API

Input a CSV list of CVE IDs to check for VC Intel

Help:

-v will check CVE list against the NVD2 endpoint
-e will check the Exploits endpoint
-iai will check the Initial Access endpoint

-c will only print the count of results in the terminal instead of the json.

Output will create output.json in the script directory with combined results of the list of CVEs requested.