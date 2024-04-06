import os
import json
import yaml

def extract_event_names(detection_dict):
    event_names = []
    for key, value in detection_dict.items():
        if isinstance(value, dict) and 'eventName' in value:
            event_name = value['eventName']
            if isinstance(event_name, list):
                event_names.extend(event_name)
            else:
                event_names.append(event_name)
    return event_names

events_directory = '../events'
# Clone the github repository https://github.com/SigmaHQ/sigma
sigma_directory = 'sigma/rules/cloud/aws/cloudtrail'
sigma_url_events = {}
sigma_github = "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/cloudtrail/"

for rootsigma, sigmadirs, sigmafiles in os.walk(sigma_directory):
                        for sigmafile in sigmafiles:
                            sigmafile_path = os.path.join(rootsigma, sigmafile)
                            with open(sigmafile_path, 'r') as file:
                                content = yaml.safe_load(file)
                                if 'detection' in content:
                                    event_names = extract_event_names(content['detection'])
                                    sigma_url_events[sigma_github + sigmafile] = event_names

for root, dirs, files in os.walk(events_directory):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    event_data = json.load(f)
                    for url, events in sigma_url_events.items():
                        if event_data['eventName'] in events:
                            sigma = {"type": "sigma", "value": url}
                            print(sigma)
                            event_data['alerting'].append(sigma)
                            #with open(file_path, 'w') as f:
                            #    json.dump(event_data, f, indent=4)