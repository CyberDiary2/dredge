import json

# Load the JSON file (replace 'ServiceTags_Public.json' with your file name)
with open('ServiceTags_Public.json') as f:
    data = json.load(f)

ip_ranges = []

# Iterate through each service entry in the JSON
for service in data['values']:
    # Each service has 'properties' containing 'addressPrefixes' which is a list of IP ranges
    prefixes = service['properties'].get('addressPrefixes', [])
    ip_ranges.extend(prefixes)

# ip_ranges now contains all IP blocks used by Azure in this file
print(ip_ranges, sep='\n')  # Or write them to a file as needed
