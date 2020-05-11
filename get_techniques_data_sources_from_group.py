from stix2 import Filter,TAXIICollectionSource
from taxii2client import Collection
import argparse
import csv

collection = Collection("https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/")
fs = TAXIICollectionSource(collection)

techniques_data_sources = {}

def get_group_by_alias(src, alias):
    return src.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('aliases', '=', alias)
    ])

def get_technique_by_group(src, stix_id):
    relations = src.relationships(stix_id, 'uses', source_only=True)
    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in relations])
    ])

parser = argparse.ArgumentParser(description='From Group to techniques & data source')
parser.add_argument('--group','-g', type=str, help='ATT&CK Group',required=True)
args = parser.parse_args()
group = args.group

group = get_group_by_alias(fs, group)[0]
techniques = get_technique_by_group(fs, group)


for item in techniques:
    techniques_data_sources.update({item.name:item.x_mitre_data_sources})

with open("techniques_datasource.csv", "w", newline="") as fd:
    wr = csv.writer(fd)
    wr.writerow(['technique','data source'])
    for k,v in techniques_data_sources.items():
        for x in v:
            wr.writerow((k,x))
