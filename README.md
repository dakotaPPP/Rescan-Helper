# Rescan-Helper
 Consolidates and optimizes the rescanning of VITs and IPs, through the use of Qualys API Requests and automatic ServiceNow webpage redirects. 
 <br />
 Python version: Python 3.11.5
# Table of Contents
* [Downloading](#downloading)
* [On first run](#on-first-run)
* [Guide](#guide)
* [Button Overview](#button-overview)
* [Extra Info](#extra-info)
> * [`VIT(s)`, `QID(s)`, and `IP(s)` lists](#vits-qids-and-ips-lists)
> * [Scan types](#scan-types)
> * [Scanner appliance groups](#scanner-appliance-groups)

## Downloading
Go to [Releases](https://github.com/dakotaPPP/Rescan-Helper/releases/) on the right hand side pane in this repository and download the .exe <br />
If instead you want to run the code via the .py file then download and import the `requirements.txt`

## On First Run
Upon your first time running the program it will create a config folder and crash<br />
This error message will ask the user to update the default configuration settings<br />
To do this go into the `config/config.json` file and update the `API_KEY`, `QUALYS_PLATFORM`, `LOGIN_URL`, `SNOW_URL`, and `SCANNER_APPLIANCE`

## Guide
1. Login to Qualys on your browser, as some buttons open up Qualys webpages<br />Click `Login to Qualys` for easy login
2. Copy your email (you can go and cherry pick the VITs or just `Ctrl + a` -> `Ctrl + c`)
3. Paste into textbox that says "Paste email's contents here"
4. Click `Look up VIT(s)` <br />
The VIT detections table will open, if you get a logout webpage just close that tab then reclick `Look up VIT(s)`
5. `Ctrl + a` -> `Ctrl + c` the **ENTIRE** VIT detections table 
6. Paste into textbox where you pasted the email
7. Click `Look up QID(s) and IP(s)`<br />
The `VIT(s)`, `QID(s)`, and `IP(s)` lists should populate<br />
In your browser the QIDs table will open, showcasing which QIDs from the VITs are Cloud Agent compatable <br />
The Cloud Agent Manager in Qualys will also open, and in order to easily check if the devices in the VITs have a cloud agent, just `Ctrl + v` into the search bar! <br />
*The above step works because the Look up QID(s) and IP(s) button copies the IPs to your clipboard* 
8. Enter your scan title in the `Title:` field
9. Choose your scan type in the `Scan type:` field
10. Click `Launch scan`<br />
The application will freeze as the request gets processed, then the Scan History in Qualys will open in the browser, showcasing the scan being launched
11. After scan finishes click `Get VITs to close`<br />
This opens up the VIT table in SNOW and showcases all the VITs that now read as FIXED in Qualys<br />
**NOTE: THERE MIGHT BE SOME LAG BETWEEN THE SCAN FINISHING AND THE RESULTS BEING UPDATED IN THE VMDR SO ALWAYS DOUBLE CHECK IF SOMETHING SEEMS WRONG**
23. Enjoy : ) 

## Button Overview
| Button name | Button function |
| ----------- | --------------- |
| Look up VIT(s) | - Uses REGEX to extract VITs from an email <br /> - Then opens detection table where VITs match |
| Look up QID(s) and IP(s) | - Populates `VIT(s)`, `QID(s)`, and `IP(s)` lists<br />- Opens a list of cloud agent compatible QIDs<br />- Opens Qualys' Cloud Agent Manager<br />- Copies IPs to clipboard |
| Login to Qualys | - Opens SSO login to Qualys |
| Open VMDR | - Pulls from the current `QID(s)` and `IP(s)` and queries the VMDR in your default browser |
| Email copy paste | - Copies the text "VIT(s) closed, vulnerabilities have been fixed according to rescan." to the clipboard |
| Get VITs to close | - Pulls from `VIT(s)`, `QID(s)`, and `IP(s)` and queries the VMDR for FIXED vulnerabilities<br />- Opens up a pop up window and a table in SNOW showing which VITs can be closed|
---
## Extra info
### `VIT(s)`, `QID(s)`, and `IP(s)` lists
1. Sometimes all you have to scan is an IP and not a list of VITs<br />
In these scenerios you'll want to go to the text box under the `IP(s)` list and click the `Add` button<br />*In theory if you paste all the IPs in the format "ip1, ip2, ip3, ..." then click `Add` the scan should still work however I'd recommend just adding them one by one*<br />
2. The `Copy` button under all these lists allow for easy copying and pasting of the entire list<br />Note: copying is in format entry1, entry2, entry3, ...

### Scan types
| Type | Fields Required |
| ---- | ---- |
| Custom QID(s) | `Title`, `QID(s)`, and `IP(s)` |
| Internal Default | `Title` and `IP(s)` |
| Dead Host | `Title` and `IP(s)` |