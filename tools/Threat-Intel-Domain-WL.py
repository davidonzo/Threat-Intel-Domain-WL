#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import requests
import json
import datetime
    
def getList():
    ret = ""
    r = requests.get("https://raw.githubusercontent.com/davidonzo/Threat-Intel-Domain-WL/main/OSINT.DigitalSide-Threat-Intel-Domain-WL.txt")
    if r.status_code != 200:
        print("Unable to download OSINT DigitalSide Threat-Intel domain white list.\nReturned HTTP status code was: "+str(r.status_code))
        sys.exit()
    else:
        ret = r.text.strip().split("\n")
    
    return ret
    

def get_version():
    return int(datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
    
def doMISPWarnList(wl):
    ret = dict()
    
    ret["description"] = "OSINT DigitalSide Threat-Intel Repository - MISP Warninglist - Domain to be excluded in the daily \"latestdomains.txt\" generation process, should be marked as false positive in the related MISP event with IDS attribute not flagged"
    ret["list"] = wl
    ret["matching_attributes"] = ["hostname", "domain"]
    ret["name"] = "OSINT.DigitalSide.IT WhiteList"
    ret["type"] = "hostname"
    ret["version"] = get_version()
    
    return json.dumps(ret, indent=4, separators=(",", ": "))

if __name__ == '__main__':
    getlist = getList()
    misp = doMISPWarnList(getlist)
    print(misp)

