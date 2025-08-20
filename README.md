# Rescan-Helper
 Consolidates and optimizes the rescanning of VITs and IPs, through the use of Qualys API Requests and automatic ServiceNow webpage redirects. 

 Python version: `Python 3.11.5`
# Table of Contents
* [Downloading](#downloading)
* [On first run](#on-first-run)
* [Guide](#guide)
* [Button Overview](#button-overview)
* [Extra Info](#extra-info)
  * [`VIT(s)`, `QID(s)`, and `IP(s)` lists](#vits-qids-and-ips-lists)
  * [Scan type configurations](#scan-type-configurations)

## Downloading
Go to [Releases](https://github.com/dakotaPPP/Rescan-Helper/releases/) on the right hand side pane in this repository and download the .exe

If instead you want to run the code via the .py file then follow the steps below:
1. Download the [.zip file](https://github.com/dakotaPPP/Rescan-Helper/archive/refs/heads/main.zip) and extract 
2. To install the required packages navigate to the directory of requirements.txt and run `pip install -r requirements.txt`

## On First Run
Upon your first time running the program it will create a config folder in your appdata


To change your configurations click the black button with the gear icon at the top right of the screen and then apply changes

Finally change the `Scan type:` settings by clicking the purple gear icon to the right of the drop down

## Guide
1. Login to Qualys on your browser, as some buttons open up Qualys webpages

    Click `Login to Qualys` for easy login

2. Copy your email (you can go and cherry pick the VITs or just `Ctrl + a` -> `Ctrl + c`)
3. Paste into textbox that says "Paste email's contents here"
4. Click `Look up VIT(s)`

    The `VIT(s)`, `QID(s)`, and `IP(s)` lists should populate

    In your browser the QIDs table will open, showcasing which QIDs from the VITs are Cloud Agent compatible

    The Cloud Agent Manager in Qualys will also open, and in order to easily check if the devices in the VITs have a cloud agent, just `Ctrl + v` into the search bar!

    > *The above step works because the Look up VIT(s) button copies the CIs to your clipboard* 
5. Enter your scan title in the `Title:` field
6. Choose your scan type in the `Scan type:` field
7. Click `Launch scan`

    The application will freeze as the request gets processed, then the Scan History in Qualys will open in the browser, showcasing the scan being launched
8. After scan finishes click `Get VITs to close`

    This opens up the VIT table in SNOW and showcases all the VITs that now read as FIXED in Qualys

    > **NOTE: THERE MIGHT BE SOME LAG BETWEEN THE SCAN FINISHING AND THE RESULTS BEING UPDATED IN THE VMDR SO ALWAYS DOUBLE CHECK IF SOMETHING SEEMS WRONG**
23. Enjoy : ) 

## Button Overview
| Button name | Button function |
| ----------- | --------------- |
| Look up VIT(s) | - Uses REGEX to extract VITs from an email <br /> - Populates `VIT(s)`, `QID(s)`, and `IP(s)` lists<br />- Opens a list of cloud agent compatible QIDs<br />- Opens Qualys' Cloud Agent Manager<br />- Copies CIs to clipboard |
| Login to Qualys | - Opens login page to Qualys |
| Open VMDR | - Pulls from the current `QID(s)` and `IP(s)` and queries the VMDR in your default browser |
| Email copy paste | - Copies the text "VIT(s) closed, vulnerabilities have been fixed according to rescan." to the clipboard |
| Get VITs to close | - Pulls from `VIT(s)`, `QID(s)`, and `IP(s)` and queries the VMDR for FIXED vulnerabilities<br />- Opens up a pop up window and a table in SNOW showing which VITs can be closed|
---
## Extra info
### `VIT(s)`, `QID(s)`, and `IP(s)` lists
1. Sometimes all you have to scan is an IP and not a list of VITs

    In these scenarios you'll want to go to the text box under the `IP(s)` list and click the `Add` button
    
    *In theory if you paste all the IPs in the format "ip1, ip2, ip3, ..." then click `Add` the scan should still work however I'd recommend just adding them one by one*

2. The `Copy` button under all these lists allow for easy copying and pasting of the entire list

    Note: copying is in format entry1, entry2, entry3, ...

### Scan type configurations
| Search List ID | Fields Required |
| ---- | ---- |
| `not NULL` | `Title`, `QID(s)`, and `IP(s)` |
| `NULL` | `Title` and `IP(s)` |
