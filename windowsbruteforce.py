
import subprocess
import csv
from collections import defaultdict
from datetime import datetime, timedelta
import re
import pandas as pd
import smtplib
from email.message import EmailMessage 


# Variable that are set by the user
email = "bruteforcedetector@gmail.com" # Email to send alerts from
password = "nffv pisg wdhd oxjg" # App password for email
to_address = "laddagat@gmu.edu"  # Update with recipient's email address

time_window = timedelta(minutes=1) # Time window for brute force attempts, default is 1 minute
failed_attempts_threshold = 10 # Threshold for brute force attempts
ssh_log_file_path = r"C:\Users\likhitha_a\Desktop\sshlog.csv" # Location you'd like to store SSH log
brute_force_log_file = r'C:\Users\likhitha_a\Desktop\brute_force_attempts.csv' # Location and name of brute force detected attempts

# Modify the path in the powershell command. This can be found right after the the email_alert function


# Function for sending email alerts
def email_alert(dataframe):
   
    # Server configuration + connecting to the email server

    # The port number (2nd parameter) can be modified
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    
    # Send an email alert for each item in the dataframe
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
        
        # Send email
        server.send_message(msg)
        

    server.quit()
    

 
# Define the PowerShell command to export the OpenSSH operational event log to a CSV file
# modify the path in the powershell command!    
powershell_command = r'''
Get-WinEvent -LogName "OpenSSH/Operational" | 
Where-Object { $_.Message -like "sshd: Failed*" } |
Export-Csv -Path "C:\Users\likhitha_a\Desktop\sshlog.csv" -NoTypeInformation
'''

# Run the PowerShell command
subprocess.run(["powershell", "-Command", powershell_command])

# Dictionary to IP addresses and timestamps for all failed attempts
failed_attempts = defaultdict(list)

# Regular expression pattern to extract IP address from the message
ip_pattern = r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

# Open the SSH log as csv file
# Go through log and all IP addresses and the timestamps for each failed login attemp
with open(ssh_log_file_path, newline='', encoding='utf-8') as csvfile:
   csv_reader = csv.reader(csvfile)
   for row in csv_reader:
       # Skip the first line in log
        if (row[16] != "TimeCreated"):
            # Format timestamp to datetime
            timestamp = datetime.strptime(row[16], "%m/%d/%Y %I:%M:%S %p")
            message = row[0]
            # Search for IP address with regex pattern
            match = re.search(ip_pattern, message)
            if match:
                ip_address = match.group(1)
                # Add IP address and matching timestamp to dictionary
                failed_attempts[ip_address].append(timestamp)
            
            

# Dictionary to store all identified brute force attempts
potential_attacks = defaultdict(list)

# For each IP address, determined if the number of failed attempts in a particular 
# Time interval exceed the threshold for failed attempts
for ip_address, timestamps in failed_attempts.items():
    timestamps.sort()  
    i = 0

    # Goes through all the timestamps for each IP address
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
    # Write dataframee to CSV file if file doesn't exist
    df.to_csv(brute_force_log_file, index=False)
   
    email_alert(df)