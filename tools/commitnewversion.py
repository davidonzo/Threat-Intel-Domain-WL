#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import requests
import json
import datetime
    
def getList():
    ret = ""
    r = open('../OSINT.DigitalSide-Threat-Intel-Domain-WL.txt', 'r')
    ret = r.read().strip().split("\n")
    
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
    
def writeNewMISPWL(mispwl):
    f = open('../misp-warning-list/OSINT.DigitalSide-Threat-Intel-Domain-WL.misp.json', 'w')
    f.write(mispwl)
    f.close()

if __name__ == '__main__':
    getlist = getList()
    misp = doMISPWarnList(getlist)
    writeWL = writeNewMISPWL(misp)
    print("")
    print("###############################")
    print("OSINT.DigitalSide.IT Domain white list succefully updated!")
    print("Now merge the changes to your forked repository and than submit a pull request to https://github.com/davidonzo/Threat-Intel-Domain-WL")
    print("###############################")
    print("")
    print("Thanks for the time you spent on this project!")
    print("")

