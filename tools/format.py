import os
import json

events_directory = '../events'

for root, dirs, files in os.walk(events_directory):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    event_data = json.load(f)
                    with open(file_path, 'w') as f:
                        json.dump(event_data, f, indent=4)