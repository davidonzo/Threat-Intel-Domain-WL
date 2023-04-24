# OSINT.DigitalSide.IT Threat-Intel Domains White List
This repository is dedicated to domain white list applied to [OSINT.DigitalSide.IT Threat Intel](https://github.com/davidonzo/Threat-Intel/) repository.

## Why a domains white list is needed for the project?
Often malicious urls are spread using legitimate domains without a proper hachikng activity, but just using the domain services in a malicious way. This is the case of file sharing services, such us Dropbox, Google Drive and GitHub of course.

When a whitelisted domain is detected to expose a malicious URL, the domain name will be omitted by the [malicious domains list](https://github.com/davidonzo/Threat-Intel/blob/master/lists/latestdomains.txt), and the url will be included in the [malicious urls list](https://github.com/davidonzo/Threat-Intel/blob/master/lists/latesturls.txt) for the configured retention period.

## How to use this repository with MISP Warning List
[MISP warning list](https://github.com/MISP/misp-warninglists) is a powerfull tool included in the popular Threat Intelligence platform. It is able to detect indicators in MISP events included in external lists, managed in the platform as warning list.

The purpose of this project is to provide an up to date version of the warning list to be used against the [OSINT.DigitalSide.IT MISP feed](https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/) in order to detect possible false positive in domain type attributes and if necessary, remove the IDS flag.

## How to request a domain addition/removal
Please, follow the following instructions in order to contribute to the white list maintainance.

* Fork this repository
* Clone the repository on your machine
* Edit the file *OSINT.DigitalSide-Threat-Intel-Domain-WL.txt* in the repository root adding a domain per line or removing domains on your choise
* Run the script `python3 tools/commitnewversion.py`
* Merge the local changes to your before forked repository
* Open a pull request asking to merge your fork to the main branch of this repository

Give me time to check for the new request and the repository will be updated as soon as possible.
