import os
import json
import csv

# Specify the directory containing the events and the output file path
events_directory = '../events'
output_file = '../docs/events.json'

# Specify the CSV file name
csv_file = "../docs/events.csv"

# Initialize an empty list to store all events
compiled_events = []

# Function to traverse the events directory and compile all JSON files
def compile_events(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    event_data = json.load(f)
                    compiled_events.append(event_data)

def generate_csv():
    # Define CSV headers
    headers = ["eventName", "eventSource", "awsService", "description", "mitreAttackTactics", "mitreAttackTechniques","mitreAttackSubTechniques", "usedInWild", "incidents", "researchLinks", "securityImplications", "alerting", "simulation", "permissions", "unverifiedMitreAttackTechniques"]

    with open(csv_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        writer.writeheader()
        
        for event in compiled_events:
            # Flatten lists into strings
            event['mitreAttackTactics'] = ', '.join(event['mitreAttackTactics'])
            event['mitreAttackTechniques'] = ', '.join(event['mitreAttackTechniques'])
            event['mitreAttackSubTechniques'] = ', '.join(event['mitreAttackSubTechniques'])
            event['incidents'] = json.dumps(event['incidents'])
            event['researchLinks'] = json.dumps(event['researchLinks'])
            event['alerting'] = json.dumps(event['alerting'])
            event['simulation'] = json.dumps(event['simulation'])
            event['unverifiedMitreAttackTechniques'] = json.dumps(event['unverifiedMitreAttackTechniques'])
            
            # Write event data
            writer.writerow(event)

compile_events(events_directory)
generate_csv()
