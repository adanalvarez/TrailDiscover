import os
import json
import boto3
from datetime import datetime, timedelta
import pytz
import time

# Specify the directory containing the events
events_directory = '../events'

# Initialize 2 empty lists to store all simulated and failed events
simulatedEvents = []
failedsimulation = []

def execute_commands(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    event_data = json.load(f)
                    if event_data['commandLineSimulation'] != "N/A":
                        print(event_data['commandLineSimulation'])
                        os.system(event_data['commandLineSimulation'])
                        time.sleep(1)

def check_events(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    event_data = json.load(f)
                    if event_data['commandLineSimulation'] != "N/A":
                        if check_get_event_last_60_mins(event_data['eventName']):
                            simulatedEvents.append(event_data['eventName'])
                        else:
                            failedsimulation.append(event_data['eventName'])
                        time.sleep(1)
                        
def check_get_event_last_60_mins(event):
    # Create a CloudTrail client
    client = boto3.client('cloudtrail')

    # Calculate the time range for the last 60 minutes
    end_time = datetime.now()
    start_time = end_time - timedelta(minutes=60)
    # Lookup events
    response = client.lookup_events(
        LookupAttributes=[
            {
                'AttributeKey': 'EventName',
                'AttributeValue': event
            },
        ],
        StartTime=start_time,
        EndTime=end_time,
    )

    events = response.get('Events', [])
    if events:
        print(f"{event} was called in the last 60 minutes.")
        for event in events:
            print(f"Event ID: {event['EventId']}, Event Time: {event['EventTime']}, Username: {event.get('Username')}")
        return True
    else:
        print(f"{event} was not called in the last 60 minutes.")
        return False

if __name__ == '__main__':   
    execute_commands(events_directory)
    print("Sleeping some minutes.")
    time.sleep(600)
    check_events(events_directory)
    print(f"simulatedEvents: {simulatedEvents}")
    print(f"failedsimulation: {failedsimulation}")