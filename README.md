CryptoBlocker
==============

This is a solution to block users infected with different ransomware variants.

The script will install File Server Resource Manager (FSRM), and set up the relevant configuration.

<b>Script Deployment Steps</b>

1. Checks for network shares
2. Installs FSRM
3. Create batch/PowerShell scripts used by FSRM
4. Creates a File Group in FSRM containing malicious extensions and filenames
5. Creates a File Screen in FSRM utilising this File Group, with an event notification and command notification
6. Creates File Screens utilising this template for each drive containing network shares

<b> How it Works</b>

If the user writes a malicious file (as contained in the file group) to a network share, FSRM will run the deployed script which will add a Deny permission for that user against every share.

This has been tested fairly thoroughly, and I find that at most ransomware ends up encrypting one directory before the user is blocked.

<b>NOTE: This will NOT stop variants which use randomised file extensions, don't drop README files, etc</b>

<b>Usage</b>

Just run the script.  You can easily use this script to deploy the required FSRM install, configuration and needed blocking scripts across many file servers

An event will be logged by FSRM to the Event Viewer (Source = SRMSVC, Event ID = 8215), showing who tried to write a malicious file and where they tried to write it. Use your monitoring system of choice to raise alarms, tickets, etc for this event and respond accordingly.

<b>Disclaimer</b>

This script is provided as is.  I can not be held liable if this does not thwart a ransomware infection, causes your server to spontaneously combust, results in job loss, etc.
