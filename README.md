## TripleA

This utility provides a graphical interface for interacting with the new Apple Business Manager and Apple School Manager APIs.

Its purpose is to enhance flexibility and ease of use, facilitate device and server details retrieval, and enable device assignment and unassignment.

## Created by Luis Mesquita based on:
Script created by Bart Reardon, June 11, 2025
Augmented by Anthony Darlow (CantScript), June 13, 2025
Script provided AS IS and without warranty of any kind.

Automation of creating and validating tokens when working with the AxM API based on the [script](https://github.com/bartreardon/macscripts/blob/master/create_client_assertion.sh) provided by [Bart Reardon](https://github.com/bartreardon) and also the script created based on Anthony Darlow's (CantScript) https://github.com/cantscript/AxM_API

This utility can be used as a script or as a stand-alone utility.

Both options are available on this GitHub page.

-----
### Steps
This script uses all the great work done by Bart Reardon and Anthony Darlow.

Down below you'll find Anthony's own instructions on how the script creates the `Client Assertion` and the `Access Token`.
1. [A Script](https://github.com/cantscript/AxM_API/blob/main/AxM_API/AutomationScripts/create_client_assertion.sh) that only deals with creating the `Client Assertion`.
2. Saves the `Client Assertion` to a text file, along with a date/time stamp 180 days later.
3. [A second Script](https://github.com/cantscript/AxM_API/blob/main/AxM_API/AutomationScripts/create_access_token.sh) that only handles the creation of the `Access Token`.
4. Saves the `Access Token` to a text file, along with a timestamp 60 mins later.
5. Should an `Access Token` not exist, the second script will create an `Access Token` providing the `Client Assertion` is still valid based on its date/time stamp. 
6. Should there be an `Access Token` but it’s not valid based on its timestamp, the second script will create a new valid `Access Token`, again providing the `Client Assertion` is still valid based on its date/time.
7. Enables two lines of code in the actual API script that creates/checks/renews the `Access Token` and saves the value into a variable for use in that script.

Above logic is embedded in the main TripleA Script.  

-----
### Configuring the Automation
First things first, if you haven't already, go and read [Barts blog](https://bartreardon.github.io/2025/06/11/using-the-new-api-for-apple-business-school-manager.html) so that you know how to configure ASM. From ASM, you'll need
* `The Private Key File` which will end in .pem <br>
* `Client ID` <br>
* `Key ID`


*** USING THE STAND ALONE APP ***
* Download the App
* The App can run from whatever location. It does not have a Developer ID, it is not Signed or Notarized.



*** USING THE SCRIPT ***

**Step 1** <br>
* Download the `TripleA` folder from the GitHub repo.
* It doesn't matter where this folder is saved on your device, as long as you know where you keep it as this is going to become the working folder for all of your AxM API scripts.


*** COMMON STEPS ***

**Step 2** <br>
* Take your `Private Key File` and move it into the `AxMCert` folder or any other folder as you will be able to select the file from within the utility.

**Step 3** <br>
* Run the Script/App <br>
* You will be prompted with a "First Use Screen" with a couple of instructions. If you want, you can check the box for the prompt not to be presented again.

**Step 4** <br>
* Another dialog is going to be presented, asking for the required details to create the Assertion and the Token.
* If you check the box "Save Details", the prompt will not be presented again.

**Step 5** <br>
* The next prompt is showing which actions are available for you to choose from:

* List Organization Devices
* List MDM Servers
* List Devices for MDM Server
* Read Device Information
* Create Unassigned Devices CSV
* Assign Devices
* Unassign Devices

The information will be presented graphically, and also corresponding CSV files are going to be created on the Desktop.

If you haven't already seen, here are the [Apple Documents for the [ASM Endpoints](https://developer.apple.com/documentation/appleschoolmanagerapi) or [ABM Endpoints](https://developer.apple.com/documentation/applebusinessmanagerapi)]


---
### Quick Notes
* If you want to reset the configuration, just delete the config file that is stored ~/Library/Preferences/com.w4a.triplea.plist.
* If you run the script, a log file is also created in the Logs Folder.
* If you run the App, the log file will be in /Library/Logs folder.
