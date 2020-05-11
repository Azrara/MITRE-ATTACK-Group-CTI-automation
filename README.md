# ATT&CK-techniques-data-source-automation
This script allows you to automatically get all group's MITRE ATT&CK techniques and the data source you need to detection.
It's based on "The Cyber Threat Intelligence Repository" of ATT&CK and CAPEC catalogs expressed in STIX 2.0 JSON.

Result is a CSV file that you can upload to : https://app.rawgraphs.io/ for visualization.

# Usage
```
python3 get_techniques_data_sources_from_group.py --group|-g <threat actor>
```
Use -h for help.

# Requirements
* Python3+
* STIX2 Library
* Taxii2client Library

# Usage example
Getting all techniques related to APT33.

```
python3 get_techniques_data_sources_from_group.py --group|-g APT33
```
After uploading the result in RawGraphs you will have visualizaiton of relations between techniques and data source required to detect them:

![GitHub Logo](/images/logo.png)
Format: ![Alt Text](url)
