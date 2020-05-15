from stix2 import Filter,TAXIICollectionSource
from taxii2client import Collection
import argparse
import csv

#Connect to TAXII server
collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")
fs = TAXIICollectionSource(collection)

techniques_data_sources = {}

#Get a group by its name
def get_group_by_alias(src, alias):
    return src.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('aliases', '=', alias)
    ])

#Return group's techniques
def get_technique_by_group(src, stix_id):
    relations = src.relationships(stix_id, 'uses', source_only=True)
    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in relations])
    ])

#Return all known threat actors
def get_all_groups(src):
    groups = []
    q = src.query([Filter('type', '=', 'intrusion-set')])
    for item in q:
        groups.append(item.name)
    return groups

parser = argparse.ArgumentParser(description='From Group to techniques & data source')
parser.add_argument('--group','-g', type=str, help='ATT&CK Group',required=True)
args = parser.parse_args()
group = args.group

if group not in get_all_groups(fs):
    print("Invalid Group")
    exit()

group = get_group_by_alias(fs, group)[0]
techniques = get_technique_by_group(fs, group)

#For each technique, append its required data sources
for item in techniques:
    techniques_data_sources.update({item.name:item.x_mitre_data_sources})

#Store result in a CSV file
with open("techniques_datasource.csv", "w", newline="") as fd:
    wr = csv.writer(fd)
    wr.writerow(['technique','data source'])
    for k,v in techniques_data_sources.items():
        for x in v:
            wr.writerow((k,x))
