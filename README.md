# SSH Brute Force Detection Tool - DFOR740 Final Project

## Description
The purpose of this tool is to detect brute force attacks through SSH logins. The tool utilizes SSH logs and traverses through them to identify instances where an IP address has numerous failed login attempts within a short period of time. Open detection, it will send an email to alert the user about the attempted brute force attack. There will also be a log file that the information about the detected brute force attacks will be stored in. This tool can be set up for Linux machines and Windows machines by using the appropriate Python script files provided. This tool has been tested on a Windows 11 VM and a Kali 2024.1 VM.

## Set-Up Instructions
Download the python files and move them to your desired location on the computer. In order for this tool to function as expected, the following things have to be configured properly on your machine:
### SSH Server Configuration
- **Windows**: Check if OpenSSH is installed on your machine with this command on Administrator Powershell: `Get-WindowsCapability -Online | ? Name -like 'OpenSSH*'`
  - If OpenSSH is not installed, install it with this command: `Add-WindowsCapability -Online -Name OpenSSH.Server`
  - Use Administrator Powershell to start the OpenSSH server with this command: `Start-Service -Name sshd`. You can verify that the service is "running" with this command: `Get-Service ssh*`
 
- **Kali**: Check the status of the SSH service by using this command in the terminal: `sudo service ssh status`
  - If the SSH status is "inactive", turn SSH on with this command: `sudo service ssh start`
 
It is also recommended that the firewall settings allow SSH traffic to port 22 or whatever pot is used by your machine. Check the SSH configuation files to ensure that they allow password authentication. Password authentication needs to be set to "yes". For Windows, the configuration file is typically located at _C:/ProgramData/ssh/sshd_config_. For Kali, the configuration file is typically located at _/etc/ssh/sshd_config_.

### Python Files Configuration
For both the Windows and Kali python scripts, a few changes have to be made to ensure that the tool will work on your machine. At the top of the script, there are a few variables that can be modified by the user. Read the comments carefully and make changes as necessary. The following is the list of variables the user should edit based on their preferences:
- **email**: This variable stores the email that will be used to send the email alerts. It is recommended that a new/separate email is used to send the alerts for security purposes.
- **password**: This variable stores the app password for logging into the email. The app password is different from your regular password. Refer to the "Email Configuration" section for instructions on finding the app password.
- **to_address**: This is the email that will receive the email alerts.
- **time_window**: This variable specifies what is considered a short period of time. The default value is set to 1 minute. This means that any attempts that occur within the span of one minute from the time they start are considered as one brute force attack when they are logged.
- **failed_attempts_threshold**: This is the maximum number of failed login attempts that are considred normal. Anything greater than this threshold is considered a brute force attack.
- **ssh_log_file_path**: This is the path and file name of where you want the SSH csv log to be stored on the computer. This is only applicable to the Windows machine.
- **brute_force_log_file**: This is where all the detected brute force attacks are stored. The variable should specify the file name and the file path.

### Email Configuration
The email that is used for sending the alerts needs to be set up properly. Follow the instructions below for setting up a Gmail account:
1. **Create or Use an Existing Gmail Account**
   - Go to: https://myaccount.google.com
   - Click on the Security tab on the left.
2. **Set Up Two-Step Verification**
   - Under "How you sign into Google" section, click on "Two Step Verification."
   - Enter your password if prompted.
   - Click on "Turn On Two-Step Verification."
   - Enter your phone number.
   - Verify your phone number with the code you receive.
3. **Generate an App Password**
   - Search for "app passwords" in the search bar or click on it from the menu page once you click on the back arrow.
   - Enter the app name.
   - Note the generated password. It will appear in this format: [XXXX XXXX XXXX XXXX]
4. **Use this password in the code**
   - For the email server, if you are using something other than Gmail, make sure to update the name. You can also modify the SMTP port number you'd like it to use.

### Setting Up Python Script as a Scheduled Task or Cronjob
By setting up the python script as a scheduled task on a Windows machine or as a cronjob on a Kali machine, the code would automatically get executed and send alerts at the frequency you set it to.
- **Windows**
  - Go to Task Scheduler. 
  - Under the "Actions" section found on the right hand side of the screen, click on 'Create Task".
  - In the General tab:
    - Specify the name of the task and provide a description.
    - Select the user profile that you'd like to run the task from.
  - In the Triggers tab:
    - Click on "New".
    - Select the time of when you'd like the task to start running.
    - Click on the "Repeat task every" checkbox and use the drop down menu to select how frequently you want the tool to run. You can also type in an option that is not available in the drop down menu.
    - Click on the "Stop task if it runs loger than" checkbox. The python script should run relatively fast, so you can select 30 minutes as the limit from the drop down menu.
    - Add an Expire date if desired.
    - Ensure the "Enabled" checkbox is selected.
    - Click Ok
  - In the Actions tab:
    - Click on "New"
    - Leave the action as "Start a Program"
    - In the "Program/script" field, you need to add the path to where python is installed on your system. We will be running the python file by running the python.exe command.
    - In the "Add Arguments" field, specify the name of the python file that will run.
    - In the "Start in" field, specify the directory in which the python file is stored in. The script will be executed from the directory.
    - Click Ok. You will be prompted to enter the password for your Windows machine.
  - _Troubleshooting_: Ensure that the user that is running the script has proper permissions to do so. The user needs to have batch job rights. To grant the user batch job rights, access Local Security Policy by pressing Win + R, typing secpol.msc, and hitting Enter. In Local Policies, go to "User Rights Assignment," double-click "Log on as a batch job," and add the user account if not already there. Click "OK" to confirm changes.
   
- **Kali**
  - For the terminal, open the crontab file to edit with this command: `crontab -e`
  - Add the following line to the file: `*/2 * * * * /usr/bin/python3 /home/kali/Desktop/kalibruteforce.py`
    - Make sure the path to python3 and the pythonscript are correct for your computer.
    - The line above runs the python script every 2 minutes. To change the frequency of how often the script is run, refer to this link to learn how to modify the command: https://phoenixnap.com/kb/set-up-cron-job-linux
   
## Testing
To test the tool, attempt to login to your target machines via SSH brute force. There are a variety of tools that can run an SSH brute force attack such as Metasploit, Ncrack, and Hydra. Hydra is relatively simple to use and comes installed on Kali. If it is not installed, run `sudo apt-get install hydra`. Use hydra from Kali to run a SSH brute force attack on your target machine. The following command can be run from the terminal:
`hydra -l <username_of_target_machince> -P <path_to_password_wordlist> -S <IP_address_of_target_machince> -t 4 ssh -v -I`
You can download a wordlist from the internet for testing purposes.
