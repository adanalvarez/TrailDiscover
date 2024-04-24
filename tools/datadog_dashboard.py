import json
import argparse

# Define the order for the MITRE ATT&CK tactics
tactic_order = {
    "TA0001 - Initial Access": 1,
    "TA0002 - Execution": 2,
    "TA0003 - Persistence": 3,
    "TA0004 - Privilege Escalation": 4,
    "TA0005 - Defense Evasion": 5,
    "TA0006 - Credential Access": 6,
    "TA0007 - Discovery": 7,
    "TA0008 - Lateral Movement": 8,
    "TA0009 - Collection": 9,
    "TA0011 - Command and Control": 10,
    "TA0010 - Exfiltration": 11,
    "TA0040 - Impact": 12
}

def load_data(file_path):
    """Load data from a JSON file."""
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
        return None
    except json.JSONDecodeError:
        print(f"Error: The file {file_path} is not a valid JSON.")
        return None

def group_events_by_tactics(events, filter_tactics):
    tactics = {}
    for event in events:
        for tactic in event['mitreAttackTactics']:
            if filter_tactics:
                    for tactic_to_filter in filter_tactics:
                        if tactic == tactic_to_filter:
                            if tactic not in tactics:
                                tactics[tactic] = []
                            tactics[tactic].append(event)
                        else:
                            pass
            else:
                if tactic not in tactics:
                    tactics[tactic] = []
                tactics[tactic].append(event)
    return tactics

def get_exploited_in_wild_event_names(events):
    return [event['eventName'] for event in events if event.get('usedInWild', False)]

def base_dashboard():
    return {
        "title": "TrailDiscover AWS Events Insights",
        "description": "",
        "widgets": [],
        "layout_type": "ordered",
        "template_variables": [
            {
                "name":"userIdentity.arn",
                "prefix":"@userIdentity.arn",
                "available_values":[],
                "default":"*"
            },
            {
                    "name":"network.client.ip",
                    "prefix":"@network.client.ip",
                    "available_values":[],
                    "default":"*"
            },
            {
                    "name":"account",
                    "prefix":"account",
                    "available_values":[],
                    "default":"*"
            }
        ],
        "notify_list": [],
        "reflow_type": "fixed"
    }

def logo_widget():
    return {
            "id": 2066777487,
            "definition":{
                "type":"image",
                "url":"https://traildiscover.cloud/logo.png",
                "sizing":"contain",
                "margin":"md",
                "has_background":False,
                "has_border":False,
                "vertical_align":"center",
                "horizontal_align":"center"
            },
            "layout":{
                "x":0,
                "y":0,
                "width":6,
                "height":2
            }
    }

def top_ten_events_widget(explited_in_the_wild_event_names):
    return {
        "id": 2985843941260464,
        "definition": {
            "title": "Top 10 CloudTrail Events exploited in the wild",
            "title_size": "16",
            "title_align": "left",
            "type": "toplist",
            "requests": [{
                "queries": [{
                    "data_source": "logs",
                    "name": "query1",
                    "indexes": ["*"],
                    "compute": {"aggregation": "count"},
                    "group_by": [{
                        "facet": "@evt.name",
                        "limit": 10,
                        "sort": {"order": "desc", "aggregation": "count"}
                    }],
                    "search": {"query": f"source:cloudtrail @evt.name:({' OR '.join(explited_in_the_wild_event_names)}) $userIdentity.arn $network.client.ip $account"},
                }],
                "response_format": "scalar"
            }],
            "style": {"display": {"type": "stacked", "legend": "automatic"}}
        },
        "layout": {"x": 0, "y": 0, "width": 6, "height": 2}
    }

def timeline_widget(tactics):
    formulas = []
    queries = []
    for idx, (tactic, events) in enumerate(tactics.items(), start=1):
        event_names = [event['eventName'] for event in events]
        # Append formula for the tactic
        formulas.append({
            "alias": tactic,
            "formula": f"query{idx}"
        })

        # Corresponding query for the tactic
        queries.append({
            "data_source": "logs",
            "name": f"query{idx}",
            "indexes": ["*"],
            "compute": {"aggregation": "count"},
            "search": {"query": f"source:cloudtrail @evt.name:({' OR '.join(event_names)}) $userIdentity.arn $network.client.ip $account"},
            "group_by": [],
            "storage": "hot"
        })

    # Timeline Widget for Tactics
    return {
        "id": 8265946211738036,
        "definition": {
            "title": "MITRE ATT&CK Tactics Events Timeline",
            "title_size": "16",
            "title_align": "left",
            "show_legend": True,
            "legend_layout": "auto",
            "legend_columns": ["avg","min","max","value","sum"],
            "time":{},
            "type": "timeseries",
            "requests": [{
                "formulas": formulas,
                "queries": queries,
                "response_format": "timeseries",
                "style": {"palette": "dog_classic", "line_type": "solid", "line_width": "normal"},
                "display_type": "bars"
            }],
        },
        "layout": {"x": 0, "y": 2, "width": 6, "height": 2}
    }

def traildiscover_description_widget():
    return {
            "id":2066777488,
            "definition":{
                "type":"note",
                "content":" # [TrailDiscover](https://traildiscover.cloud/)\n\nThis dashboard, built using data from traildiscover.cloud, offers a detailed visualization of AWS CloudTrail events that have been utilized or are potentially used by attackers. Events are organized according to MITRE ATT&CK tactics. Each event is presented with two widgets: one provides a description, a direct link to traildiscover.cloud, and references to related incidents and research; the other features a counter displaying the frequency of these events in your AWS environment.",
                "background_color":"white",
                "font_size":"14",
                "text_align":"left",
                "vertical_align":"top",
                "show_tick":False,
                "tick_pos":"50%",
                "tick_edge":"left",
                "has_padding":True
            },
            "layout":{
                "x":0,
                "y":2,
                "width":6,
                "height":3
            }
    }

def tactic_group(event, tactic, x_position, y_position):
    # Note widget for event details
    note_content = f"### [{event['eventName']}](https://traildiscover.cloud/#{event['awsService']}-{event['eventName']})\n\n**Description:** {event['description']}\n\n"
    
    # Adding related incidents
    if event['incidents'] != []:
        note_content += "**Related Incidents:**\n" + ''.join(
            [f"- [{link['description']}]({link['link']})\n" for link in event['incidents']]
        )

    # Adding related research
    if event['researchLinks'] != []:
        note_content += "**Related Research:**\n" + ''.join(
            [f"- [{link['description']}]({link['link']})\n" for link in event['researchLinks']]
        )

    note_widget = {
        "id": hash((tactic, event['eventName'], "note")) & 0xFFFFFFFF,
        "definition": {
            "type": "note",
            "content": note_content,
            "background_color": "white",
            "font_size": "14",
            "text_align": "left",
            "vertical_align": "top",
            "show_tick": False,
            "has_padding": True
        },
        "layout": {"x": x_position, "y": y_position, "width": 2, "height": 2}
    }
    
    # Query value widget for event counter
    query_widget = {
        "id": hash((tactic, event['eventName'], "query")) & 0xFFFFFFFF,
        "definition": {
            "title": event['eventName'],
            "title_size": "16",
            "title_align": "left",
            "type": "query_value",
            "requests": [{
                "response_format": "scalar",
                "queries": [{
                    "data_source": "logs",
                    "name": "query1",
                    "indexes": ["*"],
                    "compute": {"aggregation": "count"},
                    "search": {"query": f"source:cloudtrail @evt.name:{event['eventName']} $userIdentity.arn $network.client.ip $account"}
                }],
                "formulas": [{"formula": "query1"}]
            }],
            "autoscale": True,
            "precision": 2
        },
        "layout": {"x": x_position + 2, "y": y_position, "width": 2, "height": 2}
    }
    
    return [note_widget, query_widget]

def add_overview_group(dashboard, overview_group):
    dashboard['widgets'].append({
        "id": 8265946211738038,
        "definition": {
            "type": "group",
            "layout_type": "ordered",
            "background_color": "blue",
            "title": "Overview",
            "show_title": True,
            "widgets": overview_group
        },
        "layout": {"x": 6, "y": 0, "width": 6, "height": 5}
    })

def add_tactic_groups(dashboard, tactics):
    y_position = 5
    sorted_tactics = sorted(tactics.items(), key=lambda x: tactic_order.get(x[0], 999))
    for tactic, events in sorted_tactics:
        group_widgets, row_height = create_tactic_group_widgets(tactic, events)
        dashboard['widgets'].append({
            "id": hash(tactic) & 0xFFFFFFFF,
            "definition": {
                "type": "group",
                "layout_type": "ordered",
                "background_color": "blue",
                "title": tactic,
                "show_title": True,
                "widgets": group_widgets
            },
            "layout": {"x": 0, "y": y_position, "width": 12, "height": row_height + 2}
        })
        y_position += row_height + 2

def create_tactic_group_widgets(tactic, events):
    group_widgets = []
    x_position = 0
    y_position = 0
    max_width = 12
    widget_width = 4

    for event in events:
        if x_position + widget_width > max_width:
            x_position = 0
            y_position += 2

        group_widgets.extend(tactic_group(event, tactic, x_position, y_position))
        x_position += widget_width

    return group_widgets, y_position + 2

def create_datadog_dashboard(tactics, exploited_event_names):
    # Create base json for the dashbaord
    dashboard = base_dashboard()

    # Add TrailDiscover Logo to the dashboard
    dashboard['widgets'].append(logo_widget())
    
    # Create overview group with timeline and top ten events widgets
    overview_group = [
        timeline_widget(tactics),
        top_ten_events_widget(exploited_event_names)
    ]
    
    # Add Overview group widget to the dashboard
    add_overview_group(dashboard, overview_group)

    # Add description widget to the dashboard
    dashboard['widgets'].append(traildiscover_description_widget())
    
    # Add tactic groups to the dashboard
    add_tactic_groups(dashboard, tactics)

    return dashboard

def on_the_wild_only(events):
    on_the_wild_only_events = []
    for event in events:
        if event.get('usedInWild', False):
            on_the_wild_only_events.append(event)
    return on_the_wild_only_events

def main(args):
    events_path = '../docs/events.json'
    events = load_data(events_path)
    if args.on_the_wild_only:
        events = on_the_wild_only(events)  

    if events:
        tactics = group_events_by_tactics(events, args.tactics)
        exploited_event_names = get_exploited_in_wild_event_names(events)
        datadog_dashboard = create_datadog_dashboard(tactics, exploited_event_names)
        
        try:
            with open('../docs/datadog_dashboard.json', 'w') as file:
                json.dump(datadog_dashboard, file, indent=4)
            print("Dashboard created successfully.")
        except IOError as e:
            print(f"Failed to write dashboard to file: {e}")
    else:
        print("Failed to create dashboard due to data loading issues.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This script generates a Datadog dashboard with data from TrailDiscover.")
    parser.add_argument('--on-the-wild-only', action='store_true', help='Generates a dashboard only with events that have been seen in the wild.')
    parser.add_argument('--tactics', nargs='+', help='Generates a dashboard only with the selected MITRE ATT&CK tactics.')

    args = parser.parse_args()
    main(args)