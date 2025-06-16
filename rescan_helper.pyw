"""Contains everything for rescan helper... I should refactor at some point"""

import re
import tkinter as tk
from tkinter import scrolledtext
import webbrowser as wb
from csv import DictReader
from json import load, dump
from os import path, makedirs, getenv
import base64
import ipaddress

# thrid party imports
import requests
import customtkinter as ctk
from pyperclip import copy
#Checks if the folder config exists in current directory
#On first run, will create config folder and template config.json
rescanHelperPath = getenv("APPDATA")+"/RescanHelper"
if not path.exists(rescanHelperPath+"/config/config.json"):
    if not path.exists(rescanHelperPath+"/config"):
        makedirs(rescanHelperPath+"/config")
    if not path.exists(rescanHelperPath):
        makedirs(rescanHelperPath)

    with open(rescanHelperPath+"/config/config.json", "w", encoding="UTF-8") as f:
        # pylint: disable=line-too-long
        f.write("{\"API_KEY\":\"BASIC VXNlcm5hbWU6UGFzc3dvcmQ=\",\"QUALYS_PLATFORM\":\"YOUR_QUALYS_PLATFORM_HERE\",\"LOGIN_URL\":\"https://YOUR_LOGIN_URL_HERE\",\"SNOW_URL\":\"YOUR_SNOW_URL_HERE\",\"SCANNER_APPLIANCE\":\"scanner1,scanner2,...\",\"SCAN_LIST\":{\"CHANGE NAME IN SETTINGS\":{\"SEARCH_LIST_ID\": \"ENTER SEARCH LIST\", \"OP_ID\": \"ENTER OPTION PROFILE\"}}}")
        f.close()

def getConfig():
    config_file = open(rescanHelperPath+"/config/config.json", encoding="UTF-8")
    config = load(config_file)
    return config

class VitObject:
    def __init__(self, id, qid, ip, ci):
        self.id = str(id)
        self.qid = str(qid)
        self.ip = str(ip)
        self.ci = str(ci)

#Global variables
CONFIG = getConfig()
VITLIST: list[VitObject] = []
CLOSE_VIT_POPUPS = []
SETTINGS_POPUPS = []
SCAN_SETTINGS_POPUPS = []
CA_POPUPS = []
API_KEY: str = CONFIG["API_KEY"]
QUALYS_PLATFORM: str = CONFIG["QUALYS_PLATFORM"]
LOGIN_URL: str = CONFIG["LOGIN_URL"]
SCANNER_APPLIANCE: str = CONFIG["SCANNER_APPLIANCE"]
SNOW_URL: str = CONFIG["SNOW_URL"]
SCAN_LIST: str = CONFIG["SCAN_LIST"]

#grabs qid from listbox object
def get_qids() -> list[str]:
    qidNumbers: list[str] = []
    for qid in qids_listbox.get(0,"end"):
        qidNumbers.append(qid[4:])
    return qidNumbers

def updateSearchList(id: str) -> int:
    print("Updating search list...")
    url = f"https://qualysapi.{QUALYS_PLATFORM}/api/2.0/fo/qid/search_list/static/"

    payload = {'action': 'update', 'id': id, 'qids': ",".join(get_qids())}

    headers = {
    'X-Requested-With': 'RescanHelperAPI',
    'Authorization': API_KEY
    }

    response = requests.post(url, headers=headers, data=payload)

    if "search list updated successfully" in response.text:
        print("Search list updated!")
    else:
        print(response.text)
        print("Error, search list not update!!")
        return -1

    return 0

# Easy api requesting for launching a scan
def launchScanHelper(title, option, appliances, ips) -> int:
    print("Launching scan...")

    if len(ips) == 0:
        return -1
    url = f"https://qualysapi.{QUALYS_PLATFORM}/api/2.0/fo/scan/"

    payload = {'action': 'launch', 'scan_title': title, 'option_id': option,
               'iscanner_name':appliances, 'priority':'0', 'ip':','.join(ips)}

    headers = {
        'X-Requested-With': 'RescanHelperAPI',
        'Authorization': API_KEY
    }

    response = requests.post(url, headers=headers, data=payload)

    if "New vm scan launched" in response.text:
        return 0

    print(response.text)
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

    scan = SCAN_LIST[scan_type_var.get()]
    #Check the scan type the user selected then launch that scan
    if scan["SEARCH_LIST_ID"] != "NULL":

        #Checks if all required fields are filled out
        if len(qids_listbox.get(0, "end")) == 0:
            print("No QIDs detected, scan canceled")
            return -3
        if updateSearchList(scan["SEARCH_LIST_ID"]) == -1:
            print("Scan canceled.")
            return -4

    #Launch scan with selected scanner appliance group
    if launchScanHelper(title_entry.get(), scan["OP_ID"], SCANNER_APPLIANCE, ips_arr) == -1:
        return -5

    wb.open(f"https://qualysguard.{QUALYS_PLATFORM}/fo/scan/scanList.php")
    print("Scan launched!")
    return 0

def lookUpVITs():
    text = text_area.get("1.0", "end").strip()
    vits = re.findall(r"[Vv][Ii][Tt]\d{7,8}", text)
    # pylint: disable=line-too-long
    urlToOpen = f"https://{SNOW_URL}/now/nav/ui/classic/params/target/sn_vul_detection_list.do%3Fsysparm_query%3Dstatus%253D0%255Evulnerable_item.numberIN"+"%252C".join(vits)+"%26sysparm_first_row%3D1%26sysparm_view%3D"
    wb.open(urlToOpen)
    print("VITs looked up")

def lookUpQIDsAndIPs():
    global VITLIST
    text = text_area.get("1.0", "end").split("Integration run\n")
    if len(text) == 1:
        print("Error table wasn't copied properly!\nTo add QIDs and IPs with no VIT attached, please use the buttons under the listboxes.")
        return


    def validate_ip(ip_str):
        try:
            ipaddress.ip_address(ip_str)
        except ValueError:
            raise LookupError(f"Invalid IP address format: {ip_str}")
    # find the custom headers the user is using for their vit detection table
    # then use this to find QID, VIT, IP, and CI
    header = text[0].split("Currently in read mode.")[1].split("\n")
    header = header[3:-1]
    header.append("Integration run")
    #trims out text to only contain the rows now
    text[1] = text[1].replace("OpenSSH","")
    text = text[1].replace("\n","").split("Showing rows")[0].split("Open")
    text = text[1:]
    vits: list[str] = []
    qids: list[str] = []
    ips: list[str] = []
    cis: list[str] = []
    VITLIST.clear()
    #for each line in the copy paste area, check if VIT, QID, and IP, are present
    #if so then add VIT to global VITLIST
    #And updated the visual vits, qids, and ips array
    for entry in text:
        columns = entry.split("\t")
        columns.pop(0)
        if not columns:
            continue
        if not columns[-1]:
            columns.pop(-1)

        first_found = columns[2][:19]
        last_found = columns[2][19:38]
        last_element = columns[2][38:]

        try:
            validate_ip(last_element)
            columns = columns[:2] + [first_found] + [last_found] + [""] + [""] + [last_element] + columns[3:]
        except:
            columns = columns[:2] + [first_found] + [last_found] + [last_element] + columns[3:]

        columnDiff = len(columns) - len(header)

        #proof column text likes to use tabs for some reason, and tabs is how we differentiate between columns so we need cosolidate entries
        if columnDiff>0:
            proofIndex = header.index("Proof")
            for i in range(columnDiff):
                columns[proofIndex] += "\t"+columns[proofIndex+1]
                columns.pop(proofIndex+1)

        detectionData = {}
        for i in range(len(columns)):
            detectionData[header[i]] = columns[i]

        vit: str = detectionData["Vulnerable item"]
        if not vit.startswith("VIT"):
            raise LookupError("Error when copying data from SNOW over!")

        qid: str = str(detectionData["Vulnerability"])
        if not qid.startswith("QID"):
            raise LookupError("Error when copying data from SNOW over!")

        ip: str = detectionData["IP address"]
        validate_ip(ip)

        ci: str = detectionData["Configuration item"]

        VITLIST.append(VitObject(vit, qid, ip, ci))
        vits.append(vit)
        qids.append(qid)
        ips.append(ip)
        cis.append(ci)

    #Gets rid of duplicate values
    vits = list(set(vits))
    qids = list(set(qids))
    ips = list(set(ips))
    cis = list(set(cis))

    #Opens CA Compatible QIDs
    # pylint: disable=line-too-long
    wb.open(f"https://{SNOW_URL}/sn_vul_third_party_entry_list.do?sysparm_query=sourceSTARTSWITHQ%5Esearch_listsLIKEc97b18c21b9a4d5032ceedb1bc4bcb9f%5EORsearch_listsLIKE219bd8061b9a4d5032ceedb1bc4bcbfc%5EidIN"+"%2C".join(qids)+"&sysparm_first_row=1&sysparm_view=")
    #Opens Cloud Agent manager in Qualys
    wb.open(f"https://qualysguard.{QUALYS_PLATFORM}/portal-front/module/ca/#tab=ca-agents.datalist-agents")
    #Copies IPs to clipboard in ip1 OR ip2 OR ip3 OR ... formating
    checkIps = ' OR '.join(cis)
    copy(checkIps)

    #Clears lists and adds the new variables
    vits_listbox.delete(0, "end")
    for vit in vits:
        vits_listbox.insert("end", vit)
    vits_label.configure(text =f"{len(vits)} - VIT(s)")

    qids_listbox.delete(0, "end")
    for qid in qids:
        qids_listbox.insert("end", qid)
    qids_label.configure(text =f"{len(qids)} - QID(s)")

    ips_listbox.delete(0, "end")
    for ip in ips:
        ips_listbox.insert("end", ip)
    ips_label.configure(text =f"{len(ips)} - IP(s)")

    print("VITs, QIDs, and IPs tables populated!")

#Used for adding to listbox
def add_entry(listbox, entry):
    value = entry.get()
    if value:
        listbox.insert("end", value)
        entry.delete(0, "end")

#Used for removing from listbox
def remove_entry(listbox: tk.Listbox):
    selected_items = listbox.curselection()
    for item in selected_items[::-1]:
        listbox.delete(item)

def open_vmdr():
    qidsSearch = "vulnerabilities.vulnerability.qid%3A"+"%20OR%20vulnerabilities.vulnerability.qid:".join(get_qids())
    ipsSearch = "%20OR%20".join(ips_listbox.get(0,"end"))
    # pylint: disable=line-too-long
    wb.open(f"https://qualysguard.{QUALYS_PLATFORM}/vm/#/vulnerabilities?searchPivotToken=VULNERABILITY&source=&groupByPivot=VULNERABILITY&pageSize=50&pageNumber=0&criteria=&defaultQuery=Information%20%2CDisabled%20%2CIgnored&search="+qidsSearch+"&havingQuery="+ipsSearch)

def open_vits_fixed():
    #Allows for only 1 popup at a time
    global CLOSE_VIT_POPUPS

    def close_popup():
        global CLOSE_VIT_POPUPS
        CLOSE_VIT_POPUPS[0].destroy()
        CLOSE_VIT_POPUPS.clear()

    if len(CLOSE_VIT_POPUPS) == 1:
        close_popup()

    #Ensures pop up isn't hidden behind program
    popup = ctk.CTkToplevel()
    popup.protocol("WM_DELETE_WINDOW", close_popup)
    popup.title("VITs that can close")
    popup.after(250, lambda: popup.lift())
    popup.attributes("-topmost", True)
    popup.after_idle(popup.attributes, "-topmost", False)

    #Creates a GUI showcasing the VITs fixed
    listbox = tk.Listbox(popup, width=30, height=20, background = GREY, foreground = "white")
    listbox.pack(padx=10, pady=5)

    vitsFixed = retrieveAssetDetection(",".join(ips_listbox.get(0, "end")), ",".join(get_qids()), "Fixed")
    if len(vitsFixed) > 0:
        copy("VIT(s) closed, vulnerabilities have been fixed according to rescan.")
    for vit in vitsFixed:
        listbox.insert("end", vit)

    label = ctk.CTkLabel(popup, text=f"{len(vitsFixed)} VIT(s) are labeled\nas FIXED in VMDR")
    label.pack(pady=5)

    CLOSE_VIT_POPUPS.append(popup)
    #Opens SNOW VIT Table allowing for easy closing of VITs
    wb.open(f"https://{SNOW_URL}/sn_vul_vulnerable_item_list.do?sysparm_query=active%3Dtrue%5EnumberIN"+"%2C".join(vitsFixed)+"&sysparm_first_row=1&sysparm_view=")

#Gets VITs by checking the ip and qid of each VIT, as these should be unique per VIT
def getVitID(ip: str, qid: str) -> str:
    for vit in VITLIST:
        if vit.ip == ip and vit.qid == qid:
            return vit.id
    return "-1"

#Easy quering of the VMDR's assests
def retrieveAssetDetection(ips: str, qids: str, status: str) -> list[str]:
    url = f"https://qualysapi.{QUALYS_PLATFORM}/api/2.0/fo/asset/host/vm/detection/"
    if not ips or not qids or not status:
        print("Error missing parameter(s)!")
        return []

    payload = {'action':'list', 'ips':ips, 'qids':qids, 'status':status, 'max_days_since_last_vm_scan':3, 'output_format':'CSV_NO_METADATA'}

    headers = {
        'X-Requested-With': 'RescanHelperAPI',
        'Authorization': API_KEY
    }

    response = requests.post(url, headers=headers, data=payload)

    if response.status_code != 200:
        print(f"Error bad response\nCode: {response.status_code}\nMessage: {response.text}")
        return []

    fixedVits: list[str] = []
    #take in csv data, idk why I didn't do it this way originally
    data = response.text

    rows = DictReader(data.splitlines())

    for row in rows:
        vitID = getVitID(row['IP Address'], "QID-"+row['QID'])
        if vitID == "-1":
            continue
        fixedVits.append(vitID)

    fixedVits = list(set(fixedVits))
    return fixedVits

def openSettings():
    #Allows for only 1 popup at a time
    global SETTINGS_POPUPS, API_KEY, QUALYS_PLATFORM, LOGIN_URL, SCANNER_APPLIANCE, SNOW_URL, CONFIG, SCAN_LIST

    def encodeBase64(input):
        input_string_bytes = input.encode("utf-8")
        base64_bytes = base64.b64encode(input_string_bytes)
        base64_string = base64_bytes.decode("utf-8")
        return base64_string

    def decodeBase64(input):
        base64_bytes = input.encode("utf-8")
        output_string_bytes = base64.b64decode(base64_bytes)
        output_string = output_string_bytes.decode("utf-8")
        return output_string

    #updates all global variables and saves to config file
    def save_config():
        global API_KEY, QUALYS_PLATFORM, LOGIN_URL, SCANNER_APPLIANCE, SNOW_URL, CONFIG
        with open(rescanHelperPath+"/config/config.json", "w", encoding="UTF-8") as config_file:
            API_KEY = "BASIC " + encodeBase64(username_entry.get() + ":" + password_entry.get())
            QUALYS_PLATFORM = qualys_platform_entry.get()
            LOGIN_URL = login_url_entry.get()
            SCANNER_APPLIANCE = ",".join(scanner_appliance_listbox.get(0,"end"))
            SNOW_URL = snow_url_entry.get()

            CONFIG = {'API_KEY':API_KEY, 'QUALYS_PLATFORM':QUALYS_PLATFORM, 'LOGIN_URL':LOGIN_URL, 'SCANNER_APPLIANCE':SCANNER_APPLIANCE, 'SNOW_URL':SNOW_URL, 'SCAN_LIST':SCAN_LIST}
            dump(CONFIG, config_file, indent=4)

    def close_popup():
        global SETTINGS_POPUPS
        SETTINGS_POPUPS[0].destroy()
        SETTINGS_POPUPS.clear()

    if len(SETTINGS_POPUPS) == 1:
        close_popup()


    #Ensures pop up isn't hidden behind program
    popup = ctk.CTkToplevel()
    popup.protocol("WM_DELETE_WINDOW", close_popup)
    popup.title("Settings")
    popup.after(250, lambda: popup.lift())
    popup.attributes("-topmost", True)
    popup.after_idle(popup.attributes, "-topmost", False)

    top_ribbon_label = ctk.CTkLabel(popup, text="Settings", font=("Arial",20,"bold"))
    top_ribbon_label.pack(pady = 5)

    entriesFrame = ctk.CTkFrame(popup, fg_color=GREY_DARK)
    entriesFrame.pack(pady=10)
    #Label and their corresponding entry field
    username_label = ctk.CTkLabel(entriesFrame, text="Username:")
    username_label.grid(row=0, column=0, padx=10)
    username_entry = ctk.CTkEntry(entriesFrame, width=300)
    apiKeyDecode = decodeBase64(API_KEY.split(" ")[1]).split(":")
    username = apiKeyDecode.pop(0)
    username_entry.insert(0, username)
    username_entry.grid(row=0, column=1, padx=10, pady=5)

    password_label = ctk.CTkLabel(entriesFrame, text="Password:")
    password_label.grid(row=1, column=0, padx=10)
    password_entry = ctk.CTkEntry(entriesFrame, width=300, show="\u2022")
    password = ":".join(apiKeyDecode)
    password_entry.insert(1, password)
    password_entry.grid(row=1, column=1, padx=10, pady=5)

    def toggleHidden(entry):
        if entry.cget("show")=="\u2022":
            entry.configure(show="")
        else:
            entry.configure(show="\u2022")

    toggle_hidden_password_button = ctk.CTkButton(entriesFrame, text="👁", command=lambda: toggleHidden(password_entry),
                                                  fg_color=GREY, border_width=2, border_color=BLACK, hover_color=GREY_DARK, width=30)
    toggle_hidden_password_button.grid(row=1,column=2, padx=10)

    qualys_platform_label = ctk.CTkLabel(entriesFrame, text="Qualys Platform:")
    qualys_platform_label.grid(row=2, column=0, padx=10)
    qualys_platform_entry = ctk.CTkEntry(entriesFrame, width=300)
    qualys_platform_entry.insert(0, QUALYS_PLATFORM)
    qualys_platform_entry.grid(row=2, column=1, padx=10, pady=5)

    login_url_label = ctk.CTkLabel(entriesFrame, text="Login URL:")
    login_url_label.grid(row=3, column=0, padx=10)
    login_url_entry = ctk.CTkEntry(entriesFrame, width=300)
    login_url_entry.insert(0, LOGIN_URL)
    login_url_entry.grid(row=3, column=1, padx=10, pady=5)

    snow_url_label = ctk.CTkLabel(entriesFrame, text="SNOW URL:")
    snow_url_label.grid(row=4, column=0, padx=10)
    snow_url_entry = ctk.CTkEntry(entriesFrame, width=300)
    snow_url_entry.insert(0, SNOW_URL)
    snow_url_entry.grid(row=4, column=1, padx=10, pady=5)

    scanner_appliance_label = ctk.CTkLabel(entriesFrame, text="Scanner Appliance:")
    scanner_appliance_label.grid(row=5, column=0, padx=10)
    scanner_appliance_listbox = tk.Listbox(entriesFrame, width=49, selectmode="multiple", background=GREY, foreground=WHITE)
    scanner_appliance_listbox.grid(row=6, column=1, padx=10, pady=5)
    scanner_appliance_add_entry = ctk.CTkEntry(entriesFrame, width=300, placeholder_text="Enter scanner appliance name")
    scanner_appliance_add_entry.grid(row=5, column=1, padx=10, pady=5)
    scanner_appliance_add_button = ctk.CTkButton(entriesFrame, text="+",
                                                 command=lambda: add_entry(scanner_appliance_listbox, scanner_appliance_add_entry),
                                                 fg_color=GREEN, border_width=2, border_color=BLACK, hover_color=GREEN_DARK, width=30)
    scanner_appliance_add_button.grid(row=5, column=2, padx=5, pady=5)
    scanner_appliance_remove_button = ctk.CTkButton(entriesFrame, text="-",
                                                    command=lambda: remove_entry(scanner_appliance_listbox),
                                                    fg_color=RED, border_width=2, border_color=BLACK, hover_color=RED_DARK, width=30)
    scanner_appliance_remove_button.grid(row=6, column=2, padx=5, pady=5)

    for scanner in SCANNER_APPLIANCE.split(","):
        scanner_appliance_listbox.insert(0,scanner)

    button_frame = ctk.CTkFrame(popup)
    button_frame.pack(pady=5)
    apply_button = ctk.CTkButton(button_frame, text="Apply", command=save_config, fg_color=GREEN, border_width=2, border_color=BLACK, hover_color=GREEN_DARK, width=100)
    apply_button.grid(row = 0, column = 0, padx = 10, pady=5)

    def ok_button_function():
        save_config()
        close_popup()

    ok_button = ctk.CTkButton(button_frame, text="OK", command=ok_button_function, fg_color=GREEN, border_width=2, border_color=BLACK, hover_color=GREEN_DARK, width=100)
    ok_button.grid(row = 0, column = 1, padx=10)
    SETTINGS_POPUPS.append(popup)

# pylint: disable=too-many-statements
def openScanSettings():
    global SCAN_SETTINGS_POPUPS
    #updates all global variables and saves to config file
    scans = SCAN_LIST.copy()
    def save_config():
        global CONFIG, SCAN_LIST
        add_modify_entry()
        SCAN_LIST = scans
        with open(rescanHelperPath+"/config/config.json", "w", encoding="UTF-8") as config_file:
            refresh_scan_display()
            CONFIG = {'API_KEY':API_KEY, 'QUALYS_PLATFORM':QUALYS_PLATFORM, 'LOGIN_URL':LOGIN_URL, 'SCANNER_APPLIANCE':SCANNER_APPLIANCE, 'SNOW_URL':SNOW_URL, 'SCAN_LIST':SCAN_LIST}
            dump(CONFIG, config_file, indent=4)

    def close_popup():
        global SCAN_SETTINGS_POPUPS
        SCAN_SETTINGS_POPUPS[0].destroy()
        SCAN_SETTINGS_POPUPS.clear()
        refresh_scan_display()

    if len(SCAN_SETTINGS_POPUPS) == 1:
        close_popup()


    #Ensures pop up isn't hidden behind program
    popup = ctk.CTkToplevel()
    popup.protocol("WM_DELETE_WINDOW", close_popup)
    popup.title("Scan Settings")
    popup.after(250, lambda: popup.lift())
    popup.attributes("-topmost", True)
    popup.after_idle(popup.attributes, "-topmost", False)

    top_ribbon_label = ctk.CTkLabel(popup, text="Scan Settings", font=("Arial",20,"bold"))
    top_ribbon_label.pack(pady = 5)

    entriesFrame = ctk.CTkFrame(popup, fg_color=GREY_DARK)
    entriesFrame.pack(pady=10)

    #Label and their corresponding entry field
    name_label = ctk.CTkLabel(entriesFrame, text="Name:")
    name_label.grid(row=0, column=0, padx=5, pady=5)
    name_entry = ctk.CTkEntry(entriesFrame)
    name_entry.grid(row=0, column=1, padx=5, pady=5)

    search_id_label = ctk.CTkLabel(entriesFrame, text="Search List ID:")
    search_id_label.grid(row=1, column=0, padx=5, pady=5)
    search_id_entry = ctk.CTkEntry(entriesFrame)
    search_id_entry.grid(row=1, column=1, padx=5, pady=5)

    op_id_label = ctk.CTkLabel(entriesFrame, text="Option Profile ID:")
    op_id_label.grid(row=2, column=0, padx=5, pady=5)
    op_id_entry = ctk.CTkEntry(entriesFrame)
    op_id_entry.grid(row=2, column=1, padx=5, pady=5)

    # Function to add or modify entries in the scans dictionary
    def add_modify_entry():
        name = name_entry.get()
        search_id = search_id_entry.get()
        op_id = op_id_entry.get()

        if name and search_id and op_id:
            scans[name] = {"SEARCH_LIST_ID": search_id, "OP_ID": op_id}
            refresh_listbox()
        else:
            tk.messagebox.showerror("Error", "All fields must be filled!")

    # Function to delete selected entry
    def delete_entry():
        selected = scan_listbox.curselection()
        if selected:
            name = scan_listbox.get(selected[0])
            if name in scans:
                del scans[name]
                refresh_listbox()
                temp_scan_names = []
                for scan_name in scans:
                    temp_scan_names.append(scan_name)

                name_entry.delete(0, 'end')
                search_id_entry.delete(0, 'end')
                op_id_entry.delete(0, 'end')
                if scans:
                    name_entry.insert(0, temp_scan_names[0])
                    search_id_entry.insert(0, scans[temp_scan_names[0]]["SEARCH_LIST_ID"])
                    op_id_entry.insert(0, scans[temp_scan_names[0]]["OP_ID"])
        else:
            tk.messagebox.showerror("Error", "Please select an entry to delete.")

    # Refresh the listbox to show updated scan entries
    def refresh_listbox():
        scan_listbox.delete(0, 'end')
        for name in scans:
            scan_listbox.insert('end', name)

    def on_listbox_select(event):
        selected = scan_listbox.curselection()
        if selected:
            name = scan_listbox.get(selected[0])
            if name in scans:
                # Populate the entry fields with selected entry's data
                name_entry.delete(0, 'end')
                name_entry.insert(0, name)
                search_id_entry.delete(0, 'end')
                search_id_entry.insert(0, scans[name]["SEARCH_LIST_ID"])
                op_id_entry.delete(0, 'end')
                op_id_entry.insert(0, scans[name]["OP_ID"])

    # Buttons for adding, modifying, and deleting entries
    add_button = ctk.CTkButton(entriesFrame, text="+", command=add_modify_entry, fg_color=GREEN, border_width=2, border_color=BLACK, hover_color=GREEN_DARK, width=30)
    add_button.grid(row=2, column=2, padx=5, pady=5)

    delete_button = ctk.CTkButton(entriesFrame, text="-", command=delete_entry, fg_color=RED, border_width=2, border_color=BLACK, hover_color=RED_DARK, width=30)
    delete_button.grid(row=3, column=2, padx=5, pady=5)

    # Listbox to show current entries
    scan_listbox = tk.Listbox(entriesFrame, width=22, height=6, background = GREY, foreground = "white")
    scan_listbox.grid(row=3, column=1, padx=5, pady=5)

    scan_listbox.bind("<<ListboxSelect>>", on_listbox_select)

    button_frame = ctk.CTkFrame(popup)
    button_frame.pack(pady=5)
    apply_button = ctk.CTkButton(button_frame, text="Apply", command=save_config, fg_color=GREEN, border_width=2, border_color=BLACK, hover_color=GREEN_DARK, width=100)
    apply_button.grid(row = 0, column = 0, padx = 10, pady=5)

    def ok_button_function():
        save_config()
        close_popup()

    ok_button = ctk.CTkButton(button_frame, text="OK", command=ok_button_function, fg_color=GREEN, border_width=2, border_color=BLACK, hover_color=GREEN_DARK, width=100)
    ok_button.grid(row = 0, column = 1, padx=10)

    refresh_listbox()
    SCAN_SETTINGS_POPUPS.append(popup)

#Easy to edit and read HEX values of colors used in the GUI
PURPLE = "#8026FF"
PURPLE_DARK = "#402491"
RED = "#FF1A58"
RED_DARK = "#AD0047"
BLUE = "#0091DA"
BLUE_DARK = "#00598A"
GREEN = "#4FB947"
GREEN_DARK = "#397934"
WHITE = "#FFFFFF"
BLACK = "#000000"
GREY = "#343638"
GREY_DARK = "#242424"

# Initialize the main window
root = ctk.CTk()
root.title("Rescan Helper")

# Initialize CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

top_ribbon_label = ctk.CTkLabel(root, text="Rescan Helper", font=("Arial",20,"bold"))
top_ribbon_label.pack(pady = 5)
# Create a scrolled text area
text_area = scrolledtext.ScrolledText(root, wrap="word", width=55, height=6, background = GREY, foreground = "white")
text_area.insert("1.0", "Paste email's contents here")
text_area.pack(padx=10, pady=10)

# Create a frame for the buttons
button_frame = ctk.CTkFrame(root)
button_frame.pack(pady=10)

# Create the buttons
button_vits = ctk.CTkButton(button_frame, text="Look up VIT(s)", command=lookUpVITs, fg_color=PURPLE, border_width=2, border_color=BLACK, hover_color=PURPLE_DARK)
button_vits.grid(row=0, column=0, padx=10, pady=5)

button_qids_ips = ctk.CTkButton(button_frame, text="Look up QID(s) and IP(s)", command=lookUpQIDsAndIPs, fg_color=PURPLE, border_width=2, border_color=BLACK, hover_color=PURPLE_DARK)
button_qids_ips.grid(row=0, column=1, padx=10)

# Create a frame for the list boxes and their controls
list_frame = ctk.CTkFrame(root)
list_frame.pack(pady=10, padx=20)

# VITs list box and controls
vits_listbox = tk.Listbox(list_frame, width=20, height=10, background = GREY, foreground = "white", selectmode="multiple")
vits_listbox.grid(row=0, column=0, padx=10)
vits_label = ctk.CTkLabel(list_frame, text="VIT(s)")
vits_label.grid(row=1, column=0, padx=10, pady=5)
vits_add_entry = ctk.CTkEntry(list_frame)
vits_add_entry.grid(row=2, column=0, padx=10, pady=5)
vits_add_button = ctk.CTkButton(list_frame, text="Add", command=lambda: add_entry(vits_listbox, vits_add_entry), fg_color=GREEN, border_width=2, border_color=BLACK, hover_color=GREEN_DARK)
vits_add_button.grid(row=3, column=0, padx=10, pady=5)
vits_remove_button = ctk.CTkButton(list_frame, text="Remove", command=lambda: remove_entry(vits_listbox), fg_color=RED, border_width=2, border_color=BLACK, hover_color=RED_DARK)
vits_remove_button.grid(row=4, column=0, padx=10, pady=5)
vits_copy_button = ctk.CTkButton(list_frame, text="Copy", command=lambda: copy(", ".join(vits_listbox.get(0,"end"))), fg_color=BLUE, border_width=2, border_color=BLACK, hover_color=BLUE_DARK)
vits_copy_button.grid(row=5,column=0, padx=10, pady=5)


# QIDs list box and controls
qids_listbox = tk.Listbox(list_frame, width=20, height=10, background = GREY, foreground = "white", selectmode="multiple")
qids_listbox.grid(row=0, column=1, padx=10)
qids_label = ctk.CTkLabel(list_frame, text="QID(s)")
qids_label.grid(row=1, column=1, padx=10, pady=5)
qids_add_entry = ctk.CTkEntry(list_frame)
qids_add_entry.grid(row=2, column=1, padx=10, pady=5)
qids_add_button = ctk.CTkButton(list_frame, text="Add", command=lambda: add_entry(qids_listbox, qids_add_entry), fg_color=GREEN, border_width=2, border_color=BLACK, hover_color=GREEN_DARK)
qids_add_button.grid(row=3, column=1, padx=10, pady=5)
qids_remove_button = ctk.CTkButton(list_frame, text="Remove", command=lambda: remove_entry(qids_listbox), fg_color=RED, border_width=2, border_color=BLACK, hover_color=RED_DARK)
qids_remove_button.grid(row=4, column=1, padx=10, pady=5)
qids_copy_button = ctk.CTkButton(list_frame, text="Copy", command=lambda: copy(", ".join(qids_listbox.get(0,"end"))), fg_color=BLUE, border_width=2, border_color=BLACK, hover_color=BLUE_DARK)
qids_copy_button.grid(row=5,column=1, padx=10, pady=5)


# IPs list box and controls
ips_listbox = tk.Listbox(list_frame, width=20, height=10, background = GREY, foreground = "white", selectmode="multiple")
ips_listbox.grid(row=0, column=2, padx=10)
ips_label = ctk.CTkLabel(list_frame, text="IP(s)")
ips_label.grid(row=1, column=2, padx=10, pady=5)
ips_add_entry = ctk.CTkEntry(list_frame)
ips_add_entry.grid(row=2, column=2, padx=10, pady=5)
ips_add_button = ctk.CTkButton(list_frame, text="Add", command=lambda: add_entry(ips_listbox, ips_add_entry), fg_color=GREEN, border_width=2, border_color=BLACK, hover_color=GREEN_DARK)
ips_add_button.grid(row=3, column=2, padx=10, pady=5)
ips_remove_button = ctk.CTkButton(list_frame, text="Remove", command=lambda: remove_entry(ips_listbox), fg_color=RED, border_width=2, border_color=BLACK, hover_color=RED_DARK)
ips_remove_button.grid(row=4, column=2, padx=10, pady=5)
ips_copy_button = ctk.CTkButton(list_frame, text="Copy", command=lambda: copy(", ".join(ips_listbox.get(0,"end"))), fg_color=BLUE, border_width=2, border_color=BLACK, hover_color=BLUE_DARK)
ips_copy_button.grid(row=5,column=2, padx=10, pady=5)

# Create a frame for the buttons
button_frame2 = ctk.CTkFrame(root)
button_frame2.pack(pady=10)

#Buttons
button_login = ctk.CTkButton(button_frame2, text="Login to Qualys", command=lambda: wb.open(LOGIN_URL), fg_color=PURPLE, border_width=2, border_color=BLACK, hover_color=PURPLE_DARK)
button_login.grid(row=0, column=0, padx=10, pady=5)

button_open_vmdr = ctk.CTkButton(button_frame2, text="Open VMDR", command=open_vmdr, fg_color=PURPLE, border_width=2, border_color=BLACK, hover_color=PURPLE_DARK)
button_open_vmdr.grid(row=0, column=1, padx=10)

button_copy_email = ctk.CTkButton(button_frame2, text="Email copy paste",
                                  command=lambda: copy("VIT(s) closed, vulnerabilities have been fixed according to rescan."),
                                  fg_color=PURPLE, border_width=2, border_color=BLACK, hover_color=PURPLE_DARK)
button_copy_email.grid(row=1, column=0, pady=5, padx=10)

button_get_vits_to_close = ctk.CTkButton(button_frame2, text="Get VITs to close", command=open_vits_fixed, fg_color=PURPLE, border_width=2, border_color=BLACK, hover_color=PURPLE_DARK)
button_get_vits_to_close.grid(row=1, column=1, pady=5, padx=10)

# Create a frame for the dropdown and launch scan button
bottom_frame = ctk.CTkFrame(root)
bottom_frame.pack(pady=10)

title_label = ctk.CTkLabel(bottom_frame, text="Title: ")
title_label.grid(row=0, column=0, padx=10)

title_entry = ctk.CTkEntry(bottom_frame)
title_entry.grid(row=0, column=1, padx=10, pady=5)


scan_types_names = []
def refresh_scan_display():
    scan_types_names.clear()
    for scan_name in SCAN_LIST:
        scan_types_names.append(scan_name)
    scan_type_dropdown.configure(values=scan_types_names)
    if scan_types_names:
        scan_type_var.set(scan_types_names[0])


# Create the dropdown menu
scan_type_label = ctk.CTkLabel(bottom_frame, text="Scan type:")
scan_type_label.grid(row=1, column=0, padx=10)
scan_type_var = ctk.StringVar(value=scan_types_names[0] if scan_types_names else "")

scan_type_dropdown = ctk.CTkOptionMenu(bottom_frame, variable=scan_type_var, fg_color=PURPLE, button_color=PURPLE, button_hover_color=PURPLE_DARK)
scan_type_dropdown.grid(row=1, column=1, padx=10, pady=5)
refresh_scan_display()

scan_settings = ctk.CTkButton(bottom_frame, text="⚙️", command=openScanSettings, fg_color =PURPLE, border_width=2, border_color=BLACK, hover_color=PURPLE_DARK, width=15)
scan_settings.grid(row=1, column=2, padx=5)

# Create the launch scan button
button_launch_scan = ctk.CTkButton(bottom_frame, text="Launch scan", command=launchScan, fg_color=RED, border_width=2, border_color=BLACK, hover_color=RED_DARK)
button_launch_scan.grid(row=3, column=1, padx=10, pady=5)

settingsButton = ctk.CTkButton(root, text="⚙️", command=openSettings, fg_color =GREY, border_width=1, border_color=WHITE, hover_color=GREY_DARK, width=15)
settingsButton.place(relx=1.0, rely=0.0, anchor="ne", x=-10, y=5)

# Run the application
root.mainloop()
