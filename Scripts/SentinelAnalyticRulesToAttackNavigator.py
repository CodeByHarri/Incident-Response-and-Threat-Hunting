# ANALYTIC RULE TO ATTACK NAV
import pandas as pd
import json
import glob
import os

pd.set_option('display.max_columns', None)
print(os.getcwd())

# Define the path to the analytic rules JSON files
path_to_json = 'Attack'
print(path_to_json)
json_pattern = os.path.join(path_to_json, 'content', 'Azure_Sentinel_analytics_rules*.json')
print(json_pattern)
file_list = glob.glob(json_pattern)
print(file_list)

final = pd.DataFrame()

for file in file_list:
    with open(file, 'r') as f:
        json_data = json.load(f)

    expanded_data = []
    for resource in json_data['resources']:
        properties = resource['properties']
        display_name = properties.get('displayName', None)
        enabled = properties.get('enabled', None)
        tactics = properties.get('tactics', [])
        techniques = properties.get('techniques', [])
        sub_techniques = properties.get('subTechniques', [])

        # If sub-techniques exist, use them; otherwise, use techniques
        if sub_techniques:
            for sub_technique in sub_techniques:
                expanded_data.append({
                    'displayName': display_name,
                    'tactics': tactics,
                    'technique': sub_technique,
                    'enabled': enabled
                })
        else:
            for technique in techniques:
                expanded_data.append({
                    'displayName': display_name,
                    'tactics': tactics,
                    'technique': technique,
                    'enabled': enabled
                })

    # Creating the expanded DataFrame
    expanded_df = pd.DataFrame(expanded_data)
    print(expanded_df)
    final = pd.concat([final, expanded_df], axis=0)

print(final)

# Filter only enabled analytic rules if necessary
final_enabled = final[final['enabled'] == True]

# Calculate the count of analytic rules for each technique
technique_count = final_enabled['technique'].value_counts().reset_index()
technique_count.columns = ['technique', 'count']

# Use the raw counts as the scores
technique_count['score'] = technique_count['count']

# Load the default ATT&CK Navigator layer file
with open('Attack/content/DEFAULTLAYER.json', 'r') as file:
    json_data = json.load(file)

# Mapping the technique scores
technique_score_map = dict(zip(technique_count['technique'], technique_count['score']))

# Updating the scores in the 'techniques' section of the JSON data
for technique in json_data['techniques']:
    technique_id = technique['techniqueID']
    if technique_id in technique_score_map:
        technique['score'] = technique_score_map[technique_id]
    else:
        technique['score'] = ""

# Writing the updated JSON data back to a file
updated_file_path = 'Attack/content/updated_layer.json'
with open(updated_file_path, 'w') as file:
    json.dump(json_data, file, indent=4)

print('File has been created at:', updated_file_path)
