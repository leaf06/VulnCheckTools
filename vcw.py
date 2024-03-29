import os
import requests
import json
import csv

class VulnCheckAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.vulncheck.com/v3/index"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    def get_vulncheck_data(self, cve_id, endpoint):
        url = f"{self.base_url}/{endpoint}?CVE={cve_id}"
        response = requests.get(url, headers=self.headers)
        return response

    def is_authorized(self, response):
        return response.status_code != 401

    def should_display_output(self, response_json):
        return response_json.get('_meta', {}).get('total_documents', 1) != 0

def get_api_key():
    api_key = os.environ.get('VULNCHECK_API_KEY')
    if not api_key:
        api_key = input("Enter your API key: ").strip()
    return api_key

def read_cve_ids_from_csv(filename):
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        return [row['CVE_ID'] for row in reader]

def write_json_to_file(data, filename):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)
        
def is_csv_file(filename):
    return filename.lower().endswith('.csv')

def show_help():
    print("Usage:")
    print("1. To read CVE IDs from a CSV file: Enter the filename with '.csv' extension.")
    print("2. To input a list of CVE IDs directly: Enter the CVE IDs separated by commas.")
    print("3. Specify the endpoint flag after the input: -v, -e, -iai.")
    print("   -v: vulncheck-nvd2 endpoint")
    print("   -e: exploits endpoint")
    print("   -iai: initial-access endpoint")
    print("4. Optionally add '-c' to get the count of CVEs with data without JSON details.")
    print("5. Use '-h' for help.")
    print("Example: 'input.csv -v -c' or 'CVE-2021-1234,CVE-2021-2345 -e'")
    exit()


# Check for help flag
if '-h' in os.sys.argv:
    show_help()


# Usage
api_key = get_api_key()
api = VulnCheckAPI(api_key)

user_input = input("Enter the CSV filename or a list of CVE IDs (comma-separated): ")
if is_csv_file(user_input):
    cve_list = read_cve_ids_from_csv(user_input)
else:
    cve_list = user_input.split(',')

endpoint_input = input("Enter the endpoint flag (-v, -e, -iai) and optionally '-c' for count only: ").split()
endpoint_flags = {'-v': 'vulncheck-nvd2', '-e': 'exploits', '-iai': 'initial-access'}
endpoint = next((endpoint_flags[flag] for flag in endpoint_input if flag in endpoint_flags), 'vulncheck-nvd2')
count_only = '-c' in endpoint_input

all_responses = []
for cve_id in cve_list:
    response = api.get_vulncheck_data(cve_id.strip(), endpoint)

    if api.is_authorized(response):
        response_json = response.json()
        if api.should_display_output(response_json):
            all_responses.append(response_json)
    else:
        print(f"Unauthorized access for CVE {cve_id}. Please enter a valid API key.")
        os.environ.pop('VULNCHECK_API_KEY', None)  # Remove the invalid API key
        api_key = get_api_key()
        api = VulnCheckAPI(api_key)
        break  # Break out of CVE loop if unauthorized

print(f"{len(all_responses)} out of {len(cve_list)} provided CVEs returned a response")

if not count_only:
    for response in all_responses:
        print(json.dumps(response, indent=4))

# Write combined JSON data to a file if any responses are found
if all_responses:
    output_filename = 'output.json'
    write_json_to_file(all_responses, output_filename)
    print(f"Combined JSON data has been saved to {output_filename}")
