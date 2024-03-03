from openai import OpenAI
import os
import json

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

# Specify the directory containing the events
events_directory = '../events'

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
                    if event_data['securityImplications'] == "N/A":
                        print(event_data['eventName'])
                        securityImplications = generateSecurityImplications(event_data['eventName'], event_data['awsService'])
                        print(securityImplications)
                        event_data['securityImplications'] = securityImplications
                        with open(file_path, 'w') as f:
                            json.dump(event_data, f, indent=4)

def generateSecurityImplications(event, source):
    message_content = f"Write how an attacker might use the API {event} from {source}. The response has to be: Attackers might use ${event} to XXX. The response has to be short. Example: Attackers might use DeleteTrail to disrupting AWS logging."

    response = client.chat.completions.create(
        model='gpt-4',
        messages=[
            {'role': 'user', 'content': message_content}
        ],
        temperature=0,
    )

    return response.choices[0].message.content

# Compile the events from the directory
compile_events(events_directory)