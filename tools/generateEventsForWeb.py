import os
import json

# Specify the directory containing the events and the output file path
events_directory = '../events'
output_file = '../docs/events.json'

# Initialize an empty list to store all events
compiled_events = []

# Function to traverse the events directory and compile all JSON files
def compile_events(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            print(file)
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    event_data = json.load(f)
                    compiled_events.append(event_data)

# Compile the events from the directory
compile_events(events_directory)

# Write the compiled events to the output file
with open(output_file, 'w') as outfile:
    json.dump(compiled_events, outfile, indent=4)

print(f"Compiled events into '{output_file}' successfully.")