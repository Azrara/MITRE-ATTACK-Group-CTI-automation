from stix2 import FileSystemSource
from stix2 import Filter
fs = FileSystemSource('./cti-master/enterprise-attack')

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

group = get_group_by_alias(fs, 'Cozy Bear')[0]
techniques = get_technique_by_group(fs, group)


for item in techniques:
    techniques_data_sources.update({item.name:item.x_mitre_data_sources})

print(techniques_data_sources)
