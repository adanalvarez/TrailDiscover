import os
import json
import subprocess
import shlex
import argparse
import shutil

def safely_escape_command(command):
    # Escape potentially harmful characters in the command string
    return command.replace('"', '\\"')

def process_file(file_path, copy_only=False):
    if copy_only:
        copy_file(f"{file_path}.cloudtrail") 
    else:
        with open(file_path, 'r') as f:
            event_data = json.load(f)
            for simulation in event_data.get("simulation", []):
                if simulation["type"] == "commandLine" and simulation['value'] != "N/A":
                    escaped_command = safely_escape_command(simulation['value'])
                    command = f"grimoire shell --command '{escaped_command}' -o {file_path}.cloudtrail --max-events 1 --extend-search-window 10s"
                    try:
                        args = shlex.split(command)
                        subprocess.run(args, check=True, timeout=300)
                        print(f"Command executed and output to {file_path}.cloudtrail")
                    except subprocess.CalledProcessError as e:
                        print(f"Command failed with error: {e}. Continuing with next file.")
                    except subprocess.TimeoutExpired:
                        print("Command timed out. Continuing with next file.")

def copy_file(file_path):
    target_directory = '../docs/logExamples'
    try:
        os.makedirs(target_directory, exist_ok=True)  # Ensure the target directory exists
        shutil.copy(file_path, os.path.join(target_directory, os.path.basename(file_path)))
        print(f"Copied {file_path} to {target_directory}")
    except:
        print(f"Failed to copy file: {file_path}")

def main():
    parser = argparse.ArgumentParser(description="Process event simulation files.")
    parser.add_argument('--all', action='store_true', help='Process all .json files in the directory.')
    parser.add_argument('--path', type=str, help='Path to a specific .json file to process.')
    parser.add_argument('--copy', action='store_true', help='Only copy the file to the specified directory, do not process.')

    args = parser.parse_args()
    events_directory = '../events'

    if args.copy:
        action = lambda x: process_file(x, copy_only=True)
    else:
        action = process_file

    if args.all:
        for root, dirs, files in os.walk(events_directory):
            for file in files:
                if file.endswith('.json'):
                    file_path = os.path.join(root, file)
                    action(file_path)
    elif args.path:
        if args.path.endswith('.json'):
            action(args.path)
        else:
            print("Error: The path specified does not point to a .json file.")
    else:
        print("No operation specified. Use --all or --path with or without --copy to specify your action.")

if __name__ == "__main__":
    main()
