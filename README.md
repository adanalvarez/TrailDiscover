# TrailDiscover
<p align="center">
  <img src="./docs/TrailDiscover.png" alt="TrailDiscover" width="300" />
</p>
An evolving repository of CloudTrail events with detailed descriptions, MITRE ATT&amp;CK insights, real-world incidents references, other research references and security implications.

## Why This Project Exists

I started TrailDiscover because I often wondered if certain AWS commands had been used in past cyber attacks and what information was available about them. Since most API actions create a CloudTrail event with the same name, I decided to focus on CloudTrail events, also because aproaching it this way might help using this information with SIEMs. This project is about making it easier to understand which AWS actions have been misused before, how others might be misused and the event they generate. I hope this helps people decide what to watch out for, speed up figuring out what happened in an attack, and inspire new security research.

## Website

The easiest way to consume this information is via the website: https://cloudtrail.cloud/

## What's in the Project

Here's what you'll find in TrailDiscover:
- **Events Folder**: This is the main folder, here each AWS service has its own folder and inside you will find a JSON file for each event, like `CloudTrail/DeleteTrail.json` or `Cognito/GetCredentialsForIdentity.json`.
- **Docs Folder**: This folder contains a website where you can search through the events easily. You can access the website via: https://cloudtrail.cloud/
- **Tools Folder**: This folder contains tools to put all the event JSONs into one file for the website, make a list of all events in a CSV file, and a tool to help figure out security risks with OpenAI (An OpenAI apikey is needed).

### How Events Are Structured

Each event in the json files contains:
- The name of the event (like "CreateKeyPair").
- The event source that will appear in CloudTrail (such as "ec2.amazonaws.com").
- The AWS service it's part of (for example, "EC2").
- A description of what the API call related to the event does (Almost all descriptions come from AWS official documentation).
- MITRE ATT&CK tactics and techniques that might relate to the event.
- Whether we have evidence (and there is a link to it) that the call related to the event has been used in real attacks before.
- Links to incidents and research about the call related to the event.
- A note on what security implications might come with the event (Some of them are generated with OpenAI, but I've tried to review them).

## Heads Up

This is just the start, and there's a lot of manual work behind it, so there might be mistakes. The way I've mapped events to MITRE ATT&CK tactics and techniques is my best guess, based on how these commands work and what's been seen in attacks, but there are many ways to look at it.

## How to Contribute

Prs are welcome. Here’s how you can contribute:

**Adding New Events**: You can contribute by adding new event files to the `events` folder within the respective service directory. Make sure to include all the relevant details as described in the event structure section.
**Update Event Details:** Add any new findings or details that can provide a better understanding of the event's implications, use in real-world attacks, or links to researchs where the event is mentioned.

**Updating The Web**: After adding or updating events, use the tools in the `tools` folder to generate the updated CSV and JSON files for the web. This ensures that the website stays up-to-date with the latest event information.

## Plans for the Future

- **Adding More Events**: I'll keep putting in new events and updating the info for existing ones.
- **Simulations Section**: I want to add a part about simulating these events, to help people understand and prepare better.