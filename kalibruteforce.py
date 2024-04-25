import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
import re
import pandas as pd
import smtplib
from email.message import EmailMessage


# Variables to be set by the user

email = "bruteforcedetector@gmail.com" # Update with the email you'd like to send alerts ffrom
password = "nffv pisg wdhd oxjg" # Update with app password for email
to_address = "laddagat@gmu.edu"  # Update with recipient's email address

failed_attempts_threshold = 10 # Set threshold as desired
time_window = timedelta(minutes=1) # Window for brute force attempts, default to 1 minute range
brute_force_log_file = "/home/kali/Desktop/brute_force_attempts.csv" # Where you'd like to store the detected brute force attempts


# Function sends email alert
def email_alert(dataframe):

    # Server configuration + connecting to the server

    # The port number (2nd parameter) can be modified
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password) 
   
    # Sends an email alert for each item in the dataframe
    for index, row in dataframe.iterrows():
        subject = "Brute Force Attempt Detected"
        if row['Start Time'] == row['End Time']:
            body = f"A potential brute force attack was detected from IP {row['IP Address']} at {row['Start Time']} with {row['Failed Attempts']} failed attempts."
        else:
            body = f"A potential brute force attack was detected from IP {row['IP Address']} between {row['Start Time']} and {row['End Time']} with {row['Failed Attempts']} failed attempts."
        
        # Setting up the email
        msg = EmailMessage()
        msg.set_content(body)
        msg['subject'] = subject
        msg['to'] = to_address
        msg['from'] = email
       
        # Send the email
        server.send_message(msg)
       

    server.quit()
   

 
# Command to retrieve SSH logs from the systemd journal
journalctl_command = "journalctl -u ssh.service --no-pager"

# Run journalctl command to retrieve SSH logs
completed_process = subprocess.run(journalctl_command, shell=True, text=True, capture_output=True)
ssh_log = completed_process.stdout

# Regular expression patterns- used to extract information from each log entry
ip_pattern = r"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
timestamp_pattern = r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

# Dictionary to store IP addresses and timestamps for all failed attempts
failed_attempts = defaultdict(list)

# Search for IP addresses
ip_matches = re.finditer(ip_pattern, ssh_log)
for ip_match in ip_matches:
    ip_address = ip_match.group(1)
    
    # Search for timestamps for each IP address
    timestamp_matches = re.finditer(timestamp_pattern, ssh_log)
    
    for timestamp_match in timestamp_matches:
        timestamp_str = timestamp_match.group(1)
        
        # Append current year to timestamp (SSH logs didn't have the year)
        current_year = datetime.now().year
        timestamp_str_with_year = f"{current_year} {timestamp_str}"
        
        # Format timestamp as datetime object
        timestamp = datetime.strptime(timestamp_str_with_year, "%Y %b %d %H:%M:%S")
        
        # Add the times of the failed attempts from each IP address
        if timestamp and ip_address:
            failed_attempts[ip_address].append(timestamp)


# Dictionary to store all identified brute force attempts
potential_attacks = defaultdict(list)

# For each IP address, determined if the number of failed attempts in a particular 
# Time interval exceed the threshold for failed attempts
for ip_address, timestamps in failed_attempts.items():
    timestamps.sort()  
    i = 0

    # Goes to all the timestamps for each IP address
    while i < len(timestamps):
        # Gets start time of each attempt and sets the end time as the start time
        start_time = timestamps[i]
        end_time = start_time
        count = 1
        j = i + 1

        # Counts all the timestamps that are within the time window of the start time
        while j < len(timestamps) and timestamps[j] - start_time <= time_window:
            # Updates the end time 
            end_time = timestamps[j]
            count += 1
            j += 1

        # Add to dictionary if the failed attempts are greater than the threshold    
        if count >= failed_attempts_threshold:
            potential_attacks[ip_address].append((start_time, end_time, count))
        i = j

# Format the potential brute force attacks in a list
data = []
for ip_address, attacks in potential_attacks.items():
    for start_time, end_time, count in attacks:
        # Format the info
        attack_info = {
            'IP Address': ip_address,
            'Start Time': start_time,
            'End Time': end_time,
            'Failed Attempts': count
        }
        data.append(attack_info)

# Create a dataframe from the data
df = pd.DataFrame(data)

# Append dataframe to CSV file, avoiding duplicates
try:
    existing_df = pd.read_csv(brute_force_log_file)
   
    # Initialize a list to store new rows (rows not present in existing_df)
    new_rows = []
   
    # Convert 'Start Time' and 'End Time' column in existing_df to datetime
    existing_df['Start Time'] = pd.to_datetime(existing_df['Start Time'])
    existing_df['End Time'] = pd.to_datetime(existing_df['End Time'])
   
   # Iterate through each row in the new dataframe
    for _, row in df.iterrows():
    # Check if the row already exists in the existing dataframe
        is_duplicate = False
        for _, existing_row in existing_df.iterrows():
            if (existing_row['IP Address'] == row['IP Address'] and
            existing_row['Start Time'] == row['Start Time'] and
            existing_row['End Time'] == row['End Time']):
                # If the row is a duplicate, set is_duplicate to true and break the loop
                is_duplicate = True
                break
   
    # If row is not a duplicate, add it to the list of new rows
        if not is_duplicate:
            new_rows.append(row)
           

    # If there are new rows to add, merge with existing datafram and write to CSV
    if new_rows:
        new_df = pd.DataFrame(new_rows)
        merged_df = pd.concat([existing_df, new_df])
        merged_df.to_csv(brute_force_log_file, index=False)
        email_alert(new_df)



except FileNotFoundError:
    # Write dataframe to CSV file if file doesn't exist
    df.to_csv(brute_force_log_file, index=False)
   
    email_alert(df)
