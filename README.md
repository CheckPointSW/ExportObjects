# ExportObjects
Check Point ExportObjects tool enables you to export specific types of objects from a R80.10 Management database to a .csv file, which can then be imported into any other R80.10 Management database.

This tool can be used for backups, database transfers, testing, and more.

## Instructions
Clone the repository with this command:
```git
git clone --recursive https://github.com/CheckPoint-APIs-Team/ExportObjects
```
or by clicking the Download ZIP button. In this case, the "cp_mgmt_api_python_sdk" folder will be created empty and you will need to manually download and copy the [Check Point API Python SDK](https://github.com/CheckPoint-APIs-Team/cpapi-python-sdk) content into this folder.

A typical run of the script to export all hosts will be along the lines of:

export_hosts.py -m [management server IP] -o hosts.csv

A lot more details can of course be accessed with the '-h' option.

Later on, to import these hosts into other R80.10 Management database, you execute the command mgmt_cli with the batch flag [-b]:

mgmt_cli add host -b hosts.csv

Please refer to [the mgmt_cli tool manual](https://sc1.checkpoint.com/documents/latest/APIs/index.html#cli/mgmt_cli~v1.1) for more information.

## Development Environment
The tool is developed using Python language version 2.7.9 and [Check Point API Python SDK.](https://github.com/CheckPoint-APIs-Team/cpapi-python-sdk)
