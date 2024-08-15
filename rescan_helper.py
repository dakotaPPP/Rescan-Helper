import re
from pyperclip import copy
import customtkinter as ctk
import tkinter as tk
from tkinter import scrolledtext
import webbrowser as wb
import requests
import xmltodict
from json import load
from os import path, makedirs

#Checks if the folder config exists in current directory
#On first run, will create config folder and template config.json
if not path.exists("config"):
    makedirs("config")
    f = open("config/config.json", "w")
    f.write("{\"API_KEY\":\"BASIC YOUR_AUTHENTICATION_KEY_HERE\",\"QUALYS_PLATFORM\":\"YOUR_QUALYS_PLATFORM_HERE\",\"LOGIN_URL\":\"https://YOUR_LOGIN_URL_HERE\",\"SNOW_URL\":\"YOUR_SNOW_URL_HERE\",\"SCANNER_APPLIANCE\":\"scanner1,scanner2,...\"}")
    f.close()
    raise RuntimeError("Please update the default config/config.json file!")

def get_API_key():
    with open("config/config.json") as config_file:
        config = load(config_file)
        if config["API_KEY"]== "BASIC YOUR_AUTHENTICATION_KEY_HERE":
            raise RuntimeError("Please update the default config/config.json file!")
        return config["API_KEY"]

def get_Qualys_Platform():
    with open("config/config.json") as config_file:
        config = load(config_file)
        if config["QUALYS_PLATFORM"]== "YOUR_QUALYS_PLATFORM_HERE":
            raise RuntimeError("Please update the default config/config.json file!")
        return config["QUALYS_PLATFORM"]
    
def get_LOGIN_url():
    with open("config/config.json") as config_file:
        config = load(config_file)
        if config["LOGIN_URL"]== "https://YOUR_LOGIN_URL_HERE":
            raise RuntimeError("Please update the default config/config.json file!")
        return config["LOGIN_URL"]

def get_Scanner_Appliance():
    with open("config/config.json") as config_file:
        config = load(config_file)
        if config["SCANNER_APPLIANCE"] == "scanner1, scanner2, ...":
            raise RuntimeError("Please update the default config/config.json file!")
        return config["SCANNER_APPLIANCE"]

def get_SNOW_url():
    with open("config/config.json") as config_file:
        config = load(config_file)
        if config["SNOW_URL"] == "YOUR_SNOW_URL_HERE":
            raise RuntimeError("Please update the default config/config.json file!")
        return config["SNOW_URL"]

 

#Global variables
VITLIST = []
POPUPS = []
API_KEY = get_API_key()
QUALYS_PLATFORM = get_Qualys_Platform()
LOGIN_URL = get_LOGIN_url()
SCANNER_APPLIANCE = get_Scanner_Appliance()
SNOW_URL = get_SNOW_url()

#grabs qid from listbox object
def get_qids():
    qidNumbers = []
    for qid in qids_listbox.get(0,"end"):
        qidNumbers.append(qid[4:])
    return qidNumbers

def updateSearchList():
    print("Updating search list...")
    url = f"https://qualysapi.{QUALYS_PLATFORM}/api/2.0/fo/qid/search_list/static/"

    # IF YOU EVER WANT TO CHANGE THE SEARCH LIST THAT GETS UPDATED THEN YOU WILL WANT TO CHANGE THIS VARIABLE
    SEARCH_LIST_ID = '9275783'
    payload = {'action': 'update', 'id': SEARCH_LIST_ID, 'qids': ",".join(get_qids())}

    headers = {
    'X-Requested-With': 'RescanHelperAPI',
    'Authorization': API_KEY
    }

    response = requests.post(url, headers=headers, data=payload)

    if "search list updated successfully" in response.text:
        print("Search list updated!")
    else:
        print("Error, search list not update!!")
        return -1

    return 0

# Easy api requesting for launching a scan
def launchScanHelper(title, option, appliances, ips):
    print("Launching scan...")
    
    if len(ips) == 0:
        return -1
    url = f"https://qualysapi.{QUALYS_PLATFORM}/api/2.0/fo/scan/"

    payload = {'action': 'launch', 'scan_title': title, 'option_id': option, 'iscanner_name':appliances, 'priority':'0', 'ip':','.join(ips)}

    headers = {
        'X-Requested-With': 'RescanHelperAPI',
        'Authorization': API_KEY
    }

    response = requests.post(url, headers=headers, data=payload)

    if "New vm scan launched" in response.text:
        return 0

    print("Error while launching, scan canceled.")
    return -1

# is the launch scan button function
def launchScan():

    ips_arr = ips_listbox.get(0, "end")

    if len(ips_arr) == 0:
        print("No IPs detected, scan canceled")
        return -1
    
    if len(title_entry.get()) == 0:
        print("Error empty title, scan canceled")
        return -2
    
    #Check the scan type the user selected then launch that scan
    if scan_type_var.get() == "Custom QID(s)":
        print("Running Custom QID(s) scan...")

        #Checks if all required fields are filled out
        if len(qids_listbox.get(0, "end")) == 0:
            print("No QIDs detected, scan canceled")
            return -3
        if updateSearchList() == -1:
            print("Scan canceled.")
            return -4
        
        CUSTOM_QID_OPTION_ID = '9747295'

        #Launch scan with selected scanner appliance group
        if launchScanHelper(title_entry.get(), CUSTOM_QID_OPTION_ID, SCANNER_APPLIANCE, ips_arr) == -1:
            return -5

    elif scan_type_var.get() == "Internal Default":
        print("Running internal default...")
        
        DEFAULT_OPTION_ID = '9344931'

        #Launch scan with selected scanner appliance group
        if launchScanHelper(title_entry.get(), DEFAULT_OPTION_ID, SCANNER_APPLIANCE, ips_arr) == -1:
            return -5

    elif scan_type_var.get() == "Dead Host":
        print("running dead host...")

        DEAD_HOST_OPTION_ID = '9631208'

        #Launch scan with selected scanner appliance group
        if launchScanHelper(title_entry.get(), DEAD_HOST_OPTION_ID, SCANNER_APPLIANCE, ips_arr) == -1:
            return -5
        
    wb.open(f"https://qualysguard.{QUALYS_PLATFORM}/fo/scan/scanList.php")
    print("Scan completed!")
    return 0

def lookUpVITs():
    text = text_area.get("1.0", "end").strip()
    vits = re.findall(r"[Vv][Ii][Tt]\d{7,8}", text)
    urlToOpen = f"https://{SNOW_URL}/now/nav/ui/classic/params/target/sn_vul_detection_list.do%3Fsysparm_query%3Dstatus%253D0%255Evulnerable_item.numberIN"+"%252C".join(vits)+"%26sysparm_first_row%3D1%26sysparm_view%3D"
    wb.open(urlToOpen)
    print("VITs looked up")

def lookUpQIDsAndIPs():
    global VITLIST 
    text = text_area.get("1.0", "end").split("Integration runSort in ascending order\n")
    if len(text) == 1:
        print("Error table wasn't copied properly!\nTo add QIDs and IPs with no VIT attached, please use the buttons under the listboxes.")
        return 
    
    #trims out text to only contain the rows now
    text = text[1].split("Showing rows")[0].split("Open")
    vits = []
    qids = []
    ips = []
    VITLIST.clear()
    #for each line in the copy paste area, check if VIT, QID, and IP, are present
    #if so then add VIT to global VITLIST
    #And updated the visual vits, qids, and ips array
    for entry in text:
        vit = re.findall(r"[vV][iI][tT]\d{7,8}", entry)
        qid = re.findall(r"QID-\d{4,6}", entry)
        ip = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", entry)
        if vit and qid and ip:
            VITLIST.append({'id':vit[0], 'qid':qid[0], 'ip':ip[0]})
            vits.append(vit[0])
            qids.append(qid[0])
            ips.append(ip[0])

    #Gets rid of duplicate values
    vits = list(set(vits))
    qids = list(set(qids))
    ips = list(set(ips))

    #Opens CA Compatible QIDs
    wb.open(f"https://{SNOW_URL}/sn_vul_third_party_entry_list.do?sysparm_query=sourceSTARTSWITHQ%5Esearch_listsLIKEc97b18c21b9a4d5032ceedb1bc4bcb9f%5EORsearch_listsLIKE219bd8061b9a4d5032ceedb1bc4bcbfc%5EidIN"+"%2C".join(qids)+"&sysparm_first_row=1&sysparm_view=")
    #Opens Cloud Agent manager in Qualys
    wb.open(f"https://qualysguard.{QUALYS_PLATFORM}/portal-front/module/ca/#tab=ca-agents.datalist-agents")
    #Copies IPs to clipboard in ip1 OR ip2 OR ip3 OR ... formating
    checkIps = ' OR '.join(ips)
    copy(checkIps)

    #Clears lists and adds the new variables
    vits_listbox.delete(0, "end")
    for vit in vits:
        vits_listbox.insert("end", vit)
   
    qids_listbox.delete(0, "end")
    for qid in qids:
        qids_listbox.insert("end", qid)
    
    ips_listbox.delete(0, "end")
    for ip in ips:
        ips_listbox.insert("end", ip)
    
    print("VITs, QIDs, and IPs tables populated!")

#Used for adding to listbox
def add_entry(listbox, entry):
    value = entry.get()
    if value:
        listbox.insert("end", value)
        entry.delete(0, "end")

#Used for removing from listbox
def remove_entry(listbox):
    selected_items = listbox.curselection()
    for item in selected_items[::-1]:
        listbox.delete(item)

def open_vmdr():
    qidsSearch = "vulnerabilities.vulnerability.qid%3A"+"%20OR%20vulnerabilities.vulnerability.qid:".join(get_qids())
    ipsSearch = "%20OR%20".join(ips_listbox.get(0,"end"))
    wb.open(f"https://qualysguard.{QUALYS_PLATFORM}/vm/#/vulnerabilities?searchPivotToken=VULNERABILITY&source=&groupByPivot=VULNERABILITY&pageSize=50&pageNumber=0&criteria=&defaultQuery=Information%20%2CDisabled%20%2CIgnored&search="+qidsSearch+"&havingQuery="+ipsSearch)

def open_vits_fixed():
    #Allows for only 1 popup at a time
    global POPUPS

    def close_popup():
        global POPUPS
        POPUPS[0].destroy()
        POPUPS.clear()

    if len(POPUPS) == 1:
        close_popup()
    
    #Ensures pop up isn't hidden behind program
    popup = ctk.CTkToplevel()
    popup.protocol("WM_DELETE_WINDOW", close_popup)
    popup.title("VITs that can close")
    popup.after(250, lambda: popup.lift())
    popup.attributes("-topmost", True)
    popup.after_idle(popup.attributes, "-topmost", False)

    #Creates a GUI showcasing the VITs fixed
    listbox = tk.Listbox(popup, width=30, height=20, background = "#343638", foreground = "white")
    listbox.pack(padx=10, pady=5)

    vitsFixed = retrieveAssetDetection(",".join(ips_listbox.get(0, "end")), ",".join(get_qids()), "Fixed")
    for vit in vitsFixed:
        listbox.insert("end", vit)
    
    label = ctk.CTkLabel(popup, text="The above VITs are labeled\nas FIXED in VMDR")
    label.pack(pady=5)

    POPUPS.append(popup)
    #Opens SNOW VIT Table allowing for easy closing of VITs
    wb.open(f"https://{SNOW_URL}/sn_vul_vulnerable_item_list.do?sysparm_query=active%3Dtrue%5EnumberIN"+"%2C".join(vitsFixed)+"&sysparm_first_row=1&sysparm_view=")

#Gets VITs by checking the ip and qid of each VIT, as these should be unique per VIT 
def getVitID(ip, qid):
    for vit in VITLIST:
        if (vit['ip'] == ip and vit['qid'] == qid):
            return vit['id']
    return -1

#Easy quering of the VMDR's assests
def retrieveAssetDetection(ips, qids, status):
    url = f"https://qualysapi.{QUALYS_PLATFORM}/api/2.0/fo/asset/host/vm/detection/"
    if not ips or not qids or not status:
        print("Error missing parameter(s)!")
        return []
    
    payload = {'action':'list', 'ips':ips, 'qids':qids, 'status':status}

    headers = {
        'X-Requested-With': 'RescanHelperAPI',
        'Authorization': API_KEY
    }

    response = requests.post(url, headers=headers, data=payload)
    
    if(response.status_code != 200):
        print(f"Error bad response\nCode: {response.status_code}\nMessage: {response.text}")
        return []

    #This case occurs when the response comes back empty
    if (len(response.text) < 600): 
        print("Empty response")
        return []
    data = xmltodict.parse(response.text)
    fixedVits = []

    #Jank response file from Qualys
    #HOST_LIST and DETECTION_LIST doesn't always return a list so this catches that scenerio :p
    host_list = data['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']['HOST_LIST']['HOST']
    if not isinstance(host_list, list):
        host_list = [host_list]

    for host in host_list:
        detection_list = host['DETECTION_LIST']['DETECTION']
        if not isinstance(detection_list, list):
            detection_list = [detection_list]

        for detection in detection_list:
                vitID = getVitID(host['IP'], "QID-"+detection['QID'])
                if vitID == -1:
                    continue
                fixedVits.append(vitID)
    
    fixedVits = list(set(fixedVits))
    return fixedVits

#Easy to edit and read HEX values of colors used in the GUI
PURPLE = "#8026FF"
PURPLE_DARK = "#402491"
RED = "#FF1A58"
RED_DARK = "#AD0047"
BLUE = "#0091DA"
BLUE_DARK = "#00598A"
GREEN = "#4FB947"
GREEN_DARK = "#397934"

# Initialize the main window
root = ctk.CTk()
root.geometry("500x800")
root.title("Rescan Helper")

# Initialize CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

# Create a scrolled text area
text_area = scrolledtext.ScrolledText(root, wrap="word", width=55, height=6, background = "#343638", foreground = "white")
text_area.insert("1.0", "Paste email's contents here")
text_area.pack(padx=10, pady=10)

# Create a frame for the buttons
button_frame = ctk.CTkFrame(root)
button_frame.pack(pady=10)

# Create the buttons
button_vits = ctk.CTkButton(button_frame, text="Look up VIT(s)", command=lookUpVITs, fg_color=PURPLE, border_width=2, border_color="#000000", hover_color=PURPLE_DARK)
button_vits.grid(row=0, column=0, padx=10, pady=5)

button_qids_ips = ctk.CTkButton(button_frame, text="Look up QID(s) and IP(s)", command=lookUpQIDsAndIPs, fg_color=PURPLE, border_width=2, border_color="#000000", hover_color=PURPLE_DARK)
button_qids_ips.grid(row=0, column=1, padx=10)

# Create a frame for the list boxes and their controls
list_frame = ctk.CTkFrame(root)
list_frame.pack(pady=10)

# VITs list box and controls
vits_listbox = tk.Listbox(list_frame, width=20, height=10, background = "#343638", foreground = "white")
vits_listbox.grid(row=0, column=0, padx=10)
vits_label = ctk.CTkLabel(list_frame, text="VIT(s)")
vits_label.grid(row=1, column=0, padx=10, pady=5)
vits_add_entry = ctk.CTkEntry(list_frame)
vits_add_entry.grid(row=2, column=0, padx=10, pady=5)
vits_add_button = ctk.CTkButton(list_frame, text="Add", command=lambda: add_entry(vits_listbox, vits_add_entry), fg_color=GREEN, border_width=2, border_color="#000000", hover_color=GREEN_DARK)
vits_add_button.grid(row=3, column=0, padx=10, pady=5)
vits_remove_button = ctk.CTkButton(list_frame, text="Remove", command=lambda: remove_entry(vits_listbox), fg_color=RED, border_width=2, border_color="#000000", hover_color=RED_DARK)
vits_remove_button.grid(row=4, column=0, padx=10, pady=5)
vits_copy_button = ctk.CTkButton(list_frame, text="Copy", command=lambda: copy(", ".join(vits_listbox.get(0,"end"))), fg_color=BLUE, border_width=2, border_color="#000000", hover_color=BLUE_DARK)
vits_copy_button.grid(row=5,column=0, padx=10, pady=5)


# QIDs list box and controls
qids_listbox = tk.Listbox(list_frame, width=20, height=10, background = "#343638", foreground = "white")
qids_listbox.grid(row=0, column=1, padx=10)
qids_label = ctk.CTkLabel(list_frame, text="QID(s)")
qids_label.grid(row=1, column=1, padx=10, pady=5)
qids_add_entry = ctk.CTkEntry(list_frame)
qids_add_entry.grid(row=2, column=1, padx=10, pady=5)
qids_add_button = ctk.CTkButton(list_frame, text="Add", command=lambda: add_entry(qids_listbox, qids_add_entry), fg_color=GREEN, border_width=2, border_color="#000000", hover_color=GREEN_DARK)
qids_add_button.grid(row=3, column=1, padx=10, pady=5)
qids_remove_button = ctk.CTkButton(list_frame, text="Remove", command=lambda: remove_entry(qids_listbox), fg_color=RED, border_width=2, border_color="#000000", hover_color=RED_DARK)
qids_remove_button.grid(row=4, column=1, padx=10, pady=5)
qids_copy_button = ctk.CTkButton(list_frame, text="Copy", command=lambda: copy(", ".join(qids_listbox.get(0,"end"))), fg_color=BLUE, border_width=2, border_color="#000000", hover_color=BLUE_DARK)
qids_copy_button.grid(row=5,column=1, padx=10, pady=5)


# IPs list box and controls
ips_listbox = tk.Listbox(list_frame, width=20, height=10, background = "#343638", foreground = "white")
ips_listbox.grid(row=0, column=2, padx=10)
ips_label = ctk.CTkLabel(list_frame, text="IP(s)")
ips_label.grid(row=1, column=2, padx=10, pady=5)
ips_add_entry = ctk.CTkEntry(list_frame)
ips_add_entry.grid(row=2, column=2, padx=10, pady=5)
ips_add_button = ctk.CTkButton(list_frame, text="Add", command=lambda: add_entry(ips_listbox, ips_add_entry), fg_color=GREEN, border_width=2, border_color="#000000", hover_color=GREEN_DARK)
ips_add_button.grid(row=3, column=2, padx=10, pady=5)
ips_remove_button = ctk.CTkButton(list_frame, text="Remove", command=lambda: remove_entry(ips_listbox), fg_color=RED, border_width=2, border_color="#000000", hover_color=RED_DARK)
ips_remove_button.grid(row=4, column=2, padx=10, pady=5)
ips_copy_button = ctk.CTkButton(list_frame, text="Copy", command=lambda: copy(", ".join(ips_listbox.get(0,"end"))), fg_color=BLUE, border_width=2, border_color="#000000", hover_color=BLUE_DARK)
ips_copy_button.grid(row=5,column=2, padx=10, pady=5)

# Create a frame for the buttons
button_frame2 = ctk.CTkFrame(root)
button_frame2.pack(pady=10)

#Buttons
button_login = ctk.CTkButton(button_frame2, text="Login to Qualys", command=lambda: wb.open(LOGIN_URL), fg_color=PURPLE, border_width=2, border_color="#000000", hover_color=PURPLE_DARK)
button_login.grid(row=0, column=0, padx=10, pady=5)

button_open_vmdr = ctk.CTkButton(button_frame2, text="Open VMDR", command=open_vmdr, fg_color=PURPLE, border_width=2, border_color="#000000", hover_color=PURPLE_DARK)
button_open_vmdr.grid(row=0, column=1, padx=10)

button_copy_email = ctk.CTkButton(button_frame2, text="Email copy paste", command=lambda: copy("VIT(s) closed, vulnerabilities have been fixed according to rescan."), fg_color=PURPLE, border_width=2, border_color="#000000", hover_color=PURPLE_DARK)
button_copy_email.grid(row=1, column=0, pady=5, padx=10)

button_get_vits_to_close = ctk.CTkButton(button_frame2, text="Get VITs to close", command=open_vits_fixed, fg_color=PURPLE, border_width=2, border_color="#000000", hover_color=PURPLE_DARK)
button_get_vits_to_close.grid(row=1, column=1, pady=5, padx=10)

# Create a frame for the dropdown and launch scan button
bottom_frame = ctk.CTkFrame(root)
bottom_frame.pack(pady=10)

title_label = ctk.CTkLabel(bottom_frame, text="Title: ")
title_label.grid(row=0, column=0, padx=10)

title_entry = ctk.CTkEntry(bottom_frame)
title_entry.grid(row=0, column=1, padx=10, pady=5)

# Create the dropdown menu
scan_type_label = ctk.CTkLabel(bottom_frame, text="Scan type:")
scan_type_label.grid(row=1, column=0, padx=10)
scan_type_var = ctk.StringVar(value="Custom QID(s)")
scan_type_dropdown = ctk.CTkOptionMenu(bottom_frame, variable=scan_type_var, values=["Custom QID(s)", "Internal Default", "Dead Host"], fg_color=PURPLE, button_color=PURPLE, button_hover_color=PURPLE_DARK)
scan_type_dropdown.grid(row=1, column=1, padx=10, pady=5)

# Create the launch scan button
button_launch_scan = ctk.CTkButton(bottom_frame, text="Launch scan", command=launchScan, fg_color=RED, border_width=2, border_color="#000000", hover_color=RED_DARK)
button_launch_scan.grid(row=3, column=1, padx=10, pady=5)


# Run the application
root.mainloop() 