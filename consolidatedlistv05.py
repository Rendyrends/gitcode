import logging
from netmiko import ConnectHandler, SSHDetect, NetMikoTimeoutException, NetMikoAuthenticationException
import getpass
import pandas as pd
import re
import time
from datetime import datetime
import openpyxl
import math 
import configparser

date = datetime.now().strftime("%Y-%m-%d_%H-%M")

# Configure logging
logging.basicConfig(filename=f'01 MAY Network Inventory Errors_{date}.txt', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Prompt for username and password
user = getpass.getuser()
print(f"Hello {user.upper()}")

config = configparser.ConfigParser()
config.read('config.ini')
username = config.get('credentials', 'username')
password = config.get('credentials', 'password')

# Predefined interface statuses
xe_up = "up"
xr_up = "Up"
xe_down = "down"
xr_down = "Down"
xe_down_down = "administratively"
xr_down_down = "Shutdown"


data = []  # List to store data for each device


# Function for interface counting
def count_interfaces(ssh, device_data):
    gig_up = gig_down = gig_admin_down = 0
    ten_gig_up = ten_gig_down = ten_gig_admin_down = 0
    hundred_gig_up = hundred_gig_down = hundred_gig_admin_down = 0
    etherport = ""
    membercount = 1
    interface_status = ssh.send_command("show ip interface brief", read_timeout=300)
    interface_lines = interface_status.splitlines()

    for lines in interface_lines:
        columns = lines.split()
        if "Giga" in lines and "." not in columns[0] and "/" in columns[0]:
            if columns[4].lower() == xe_up.lower():
                gig_up += 1
            elif columns[4].lower() == xe_down.lower():
                gig_down += 1
            elif columns[4].lower() == xe_down_down.lower():
                gig_admin_down += 1

        elif "Te" in lines and "." not in columns[0]:
            if columns[4].lower() == xe_up.lower():
                ten_gig_up += 1
            elif columns[4].lower() == xe_down.lower():
                ten_gig_down += 1
            elif columns[4].lower() == xe_down_down.lower():
                ten_gig_admin_down += 1
        
        elif "Port-channel" in lines:
            if columns[4].lower() == xe_up.lower():
                etherport = ssh.send_command(f'show interface {columns[0]} | include Member')
                print(etherport)
                etherports = etherport.splitlines()
                
                for members in etherports:
                    member_names = members.split()
                    member = f"Member {membercount} : {member_names[3]}"
                    membercount += 1
                    
                    print(member)
                    
                
                
   
    print("Gig interfaces:")
    print(f"Gig Up: {gig_up}, Gig Down: {gig_down},  Gig Admin Down: {gig_admin_down}")

    print("10G interfaces:")
    print(f"TenG Up: {ten_gig_up}, TenG Down: {ten_gig_down},  TenG Admin Down: {ten_gig_admin_down}")


    device_data['Gig_up'] = gig_up
    device_data['Gig_down'] = gig_down
    device_data['Gig_admin_down'] = gig_admin_down

    device_data['TenG_up'] = ten_gig_up
    device_data['TenG_down'] = ten_gig_down
    device_data['TenG_admin_down'] = ten_gig_admin_down
    
    device_data['Total 1G Ports'] =  device_data['Gig_up'] + device_data['Gig_down'] + device_data['Gig_admin_down'] 
    print(f"Total 1G Ports : {device_data['Total 1G Ports']}")
    
    device_data['Total 10G Ports'] = device_data['TenG_up'] + device_data['TenG_down'] + device_data['TenG_admin_down']
    print(f"Total 10G Ports : {device_data['Total 10G Ports']}")
    
    if device_data['Total 1G Ports']  == 0:
       device_data['1G Utilization (%)'] = None
    else:
        device_data['1G Utilization (%)'] = device_data['Gig_up'] / device_data['Total 1G Ports']
        print(f"1G Utilization {device_data['1G Utilization (%)']}")
        
    if device_data['Total 10G Ports'] == 0:
       device_data['10G Utilization (%)'] = None
    else:
        device_data['10G Utilization (%)'] = device_data['TenG_up'] / device_data['Total 10G Ports']
        print(f"10G Utilization {device_data['10G Utilization (%)']}")



def extract_and_format_platform_info(ssh, device_data):

    getPlatformInfo = ssh.send_command("show platform", read_timeout=300)
    
    platformLines = getPlatformInfo.splitlines()
    
    
    for rsp in platformLines:
        
        rsp0_match = re.search(r"0/RSP0/CPU0\s+(\S+)", rsp)
        if rsp0_match:
            device_data['RSP0'] = rsp0_match.group(1)
        
        elif "0/RSP1/CPU0" in rsp:
            rsp1_match = re.search(r"0/RSP1/CPU0\s+(\S+)", rsp)
            if rsp1_match:
                device_data['RSP1'] = rsp1_match.group(1)
                
        elif "0/RP0/CPU0" in rsp:
            rp0_match = re.search(r"0/RP0/CPU0\s+(\S+)", rsp)
            if rp0_match:
                device_data['RP0'] = rp0_match.group(1)
                
        elif "0/RP1/CPU0" in rsp:
            rp1_match = re.search(r"0/RP1/CPU0\s+(\S+)", rsp)
            if rp1_match:
                device_data['RP1'] = rp1_match.group(1)
    
    print(f"RSP0: {device_data['RSP0']}")
    print(f"RSP1: {device_data['RSP1']}")
    print(f"RP0: {device_data['RP0']}")
    print(f"RP1: {device_data['RP1']}")
   
    print("Done Extracting RSP Cards")
    
    
    # Identify MOD and MPA cards
    mod_cards = [line for line in platformLines if 'MOD' in line]
    mpa_cards = [line for line in platformLines if any(keyword in line for keyword in ['X10GE', 'X1GE', 'FLEX', 'X100GE', 'x10GE']) or 'LC' in line]

    
    mod_counter = mpa_counter = 1
    
    for mod_card_line in mod_cards:
        mod_card_type_match = re.search(r"(\S+-MOD\S+)", mod_card_line)
        if mod_card_type_match:
            mod_card_type = f"MOD CARD0{mod_counter}"
            device_data[mod_card_type] = mod_card_type_match.group(1)
            print(f"MOD CARD0{mod_counter}: {device_data[mod_card_type]}")
            mod_counter +=1
            
    
    for mpa_card_line in mpa_cards:
        mpa_card_type_match = re.search(r"(?i)(\s\S+\s*(X10GE|X1GE|FLEX|X100GE|LC))", mpa_card_line)
        if mpa_card_type_match:
            mpa_card_type = f"MPA CARD0{mpa_counter}"
            device_data[mpa_card_type] = mpa_card_type_match.group(1)
            print(f"MPA CARD0{mpa_counter}: {device_data[mpa_card_type]}")
            mpa_counter += 1
    
    print("Done categorizing cards")    

def nv_sat_count(ssh, device_data):

    sat_count = 0
    conflit = 0
    
    nv_satelite = ssh.send_command("show  nv satellite status brief")
    
    satlines = nv_satelite.splitlines()
    
    for nv in satlines:
        
        if "Connected" in nv:
            sat_count += 1
            print(sat_count)
            
        elif "Discovery Stalled" in nv:
            conflit += 1
            print(conflit)
        
    
    device_data['Connected NV_SATs'] = sat_count
    device_data['Disconnected NV_SATs'] = conflit
    
    print(f"Connected NV_SATs: {device_data['Connected NV_SATs']}")
    print(f"Disconnected NV_SATs: {device_data['Disconnected NV_SATs']}")

        
 
def process_device(device, username, password, commands):
    with open("other commands1.txt", "a") as output_file:
        try:
        
            hostname_pattern = re.compile(r"([\w\d_-]+)#$")
            pop_match = re.compile(r"(?i)place\s*:\s*(\S.*)", re.IGNORECASE)
            pop_match2 = re.compile(r"(?i)place\s*:\s*(\S.*)", re.IGNORECASE)
         
            logging_in = {
                    "device_type": "autodetect",  # Use 'autodetect' for automatic detection
                    "host": device,
                    "username": username,
                    "password": password,
                    "read_timeout_override" : 300,
                }

            # Use SSHDetect to determine the device type
            guesser = SSHDetect(**logging_in)
            device_type = guesser.autodetect()

            # Use the detected device type for connection
            logging_in["device_type"] = device_type

            with ConnectHandler(**logging_in) as ssh:
                print(f'Connecting to {device}')

                device_data = {
                    'IP Address': device,
                    'Hostname': None,
                    'Region': None,
                    'Site Name': None,
                    'Function' : None,
                    'Serial Number': None,
                    'Version' : None,
                    'Model' : None,
                    'Gig_up' : 0,
                    'Gig_down' : 0,
                    'Gig_admin_down' : 0,
                    'TenG_up' : 0,
                    'TenG_down' : 0,
                    'TenG_admin_down' : 0,
                    'HunG_up' : 0,
                    'HunG_down' : 0,
                    'HunG_admin_down' : 0,
                    'Total 1G Ports' : 0,
                    'Total 10G Ports': 0,
                    'Total 100G Ports' : 0,
                    '1G Utilization (%)': 0,
                    '10G Utilization (%)' : 0,
                    '100G Utilization (%)' : 0,
                    'Connected NV_SATs' : 0,
                    'Disconnected NV_SATs' : 0,
                    'RSP0' : 'Not Present',
                    'RSP1' : 'Not Present',
                    'RP0' : 'Not Present',
                    'RP1' : 'Not Present',
                   
                }
              
                 # Use the compiled patterns with find_prompt
                prompt = ssh.find_prompt()
                
                # Search for the compiled hostname pattern
                hostname_match = hostname_pattern.search(prompt)
                if hostname_match:
                    device_data['Hostname'] = hostname_match.group(1)
                    
                
                # Search for the compiled POP name pattern
                pop_name_match = pop_match.search(prompt)
                pop_name_match2 = pop_match2.search(prompt)
                
                if pop_name_match:
                   device_data['Site Name'] = pop_name_match.group(1)
                   print(f"POPNAME {device_data['Site Name']}")
                
                elif pop_name_match2:
                   device_data['Site Name'] = pop_name_match2.group(1)
                   print(f"POPNAME {device_data['Site Name']}")

                # Extract region and fuction based on the hostname
                if device_data['Hostname']:
                    first_letter = device_data['Hostname'][0].upper() # Region
                    last_letter = device_data['Hostname'][-1].lower() # Function
                    
                    region_mapping = { 'C': 'Central',
                                       'M': 'MP',
                                       'F': 'FS', 
                                       'G': 'GP',
                                       'K': 'KZN',
                                       'N': 'NC',
                                       'W': 'WC',
                                       }
                    function_mapping = {'a': 'APE',
                                        'b': 'BS',
                                        'm': 'MPE', 
                                        't': 'TPE',
                                        'i': 'IGW',
                                        's': 'SPE', 
                                        'r': 'RR',
                                        'l': 'LLP',
                                        }
                    
                    device_data['Region'] = region_mapping.get(first_letter, 'Unknown')
                    device_data['Function'] = function_mapping.get(last_letter, 'Unknown')
                    
                    if device_data['Hostname'].endswith('P1'):
                        device_data['Function'] = 'CORE NODE'
                    
                    elif device_data['Hostname'].endswith('PE1') or device_data['Hostname'].endswith('PE2') or device_data['Hostname'].endswith('PE02') or device_data['Hostname'].endswith('PE01') or device_data['Hostname'].endswith('PE3') or device_data['Hostname'].endswith('PE03'):
                        device_data['Function'] = 'APE'
                    
                    elif device_data['Hostname'].endswith('P1'):
                        device_data['Function'] = 'CORE NODE'
                    
                    if device_data['Hostname'].startswith('LZA'):
                    
                        if "NSB" in device_data['Hostname'] or "MWP" in device_data['Hostname'] or "NSP" in device_data['Hostname'] or "TIS" in device_data['Hostname'] or "PRY" in device_data['Hostname']:
                            device_data['Region'] = 'GP'
                        
                        elif "CPT" in device_data['Hostname'] or "BEL" in device_data['Hostname'] or "DIE" in device_data['Hostname']:
                            device_data['Region'] = 'WC'
                            
                        elif "DUR" in device_data['Hostname'] or "TDB" in device_data['Hostname'] or "PMB" in device_data['Hostname']:
                            device_data['Region'] = 'KZN'
                            
                        elif "BFN" in device_data['Hostname'] or "KIM" in device_data['Hostname']:
                            device_data['Region'] = 'FS'
                        
                        
                    if device_data['Hostname'].startswith('l'):
                        print(f"Debug: Hostname: {device_data['Hostname']}")
                        device_data['Region'] = 'LP'
                        
                    if device_data['Hostname'].startswith('e') or 'ecg' in device_data['Hostname'] or device_data['Hostname'].startswith('E'):
                        device_data['Region'] = 'EC'
                    
                    
                    if "JIDC" in device_data['Hostname'] or "CIDC" in device_data['Hostname']:
                        device_data['Function'] = "AGG"
                    
                    if "JIDC" in device_data['Hostname']:
                        device_data['Region'] = 'GP'
                        device_data['Site Name'] = "JHB ADC"
                        
                    if "CIDC" in device_data['Hostname']:
                        device_data['Region'] = 'WC'
                        device_data['Site Name'] = "CPT ADC"
                    
                    if "SR1" in device_data['Hostname']:
                        device_data['Function'] = "BNG"
                    
                print(f"Hostname: {device_data['Hostname']}")
                print(f"Region: {device_data['Region']}")
                print(f"Node Function: {device_data['Function']}")
              
                
                for cmd in commands:
                    print(f"Executing command: {cmd}")
                    cmd_output = ssh.send_command(cmd, read_timeout=300)
                    #print(f"Output: {cmd_output}")
                    
                     # Extract additional information based on the command
                    if "show version" in cmd:
                        # Extract version
                        version_match = re.search(r"Cisco IOS \s*(\S+) Software, Version (.+?)(\[|\n)", cmd_output)
                        
                        if version_match:
                            device_data['Version'] = version_match.group(2)
                            print(f"Version: {device_data['Version']}")
                            
                            if version_match.group(1) == 'XR':
                                
                                if device_data['IP Address'].startswith('172.30.') or device_data['IP Address'].startswith('172.31.'):
                                    if device_data['IP Address'].endswith('.0') or device_data['IP Address'].endswith('.1'):
                                        print("TERMINATED")
                                        break
                                
                                else:
                                
                                    #execute_show_run_hostname(ssh, device_data) #Node function, Hostname and Region
                                    extract_and_format_platform_info(ssh, device_data) #Line Card Count
                                    nv_sat_count(ssh, device_data) #Counting SAT Panels
                                    
                                    if device_data['Hostname']:
                                    
                                        if '9904' in device_data['Hostname'] or '9906' in device_data['Hostname'] or '9903' in device_data['Hostname']:
                                            if '9904' in device_data['Hostname']:
                                            
                                                print("DATA FOR 9904")
                                                inventory = ssh.send_command("show inventory | include 9904", read_timeout=300)
                                                
                                                serial_match = re.search(r"SN: (\S+)[\n\r]", inventory)  # Standard pattern
                                                if not serial_match:
                                                    serial_match = re.search(r"SN:\s*(\S+)", inventory)  # Alternative pattern 1
                                                if not serial_match:
                                                    serial_match = re.search(r"PID: .+?SN: (\S+)[\n\r]", inventory)  # Alternative pattern 2
                                                if not serial_match:
                                                    serial_match = re.search(r"PID: .+?SN:\s*(\S+)", inventory)  # Alternative pattern 3

                                                if serial_match:
                                                    device_data['Serial Number'] = serial_match.group(1)
                                                    
                                                model_match = re.search(r"PID: \s*(\S+)", inventory)
                                                if model_match:
                                                    device_data['Model'] = model_match.group(1).rstrip(",")
                                                    
                                                if not serial_match:
                                                    print("Executing command: admin show inventory chassis")
                                                    serial_cmd_output = ssh.send_command("admin show inventory chassis", read_timeout=300)
                                                    print(f"Output: {serial_cmd_output}")

                                                    # Updated serial number extraction to handle variations in format
                                                    serial_match = re.search(r"SN: (\S+)[\n\r]", serial_cmd_output)  # Standard pattern
                                                    if not serial_match:
                                                        serial_match = re.search(r"SN:\s*(\S+)", serial_cmd_output)  # Alternative pattern 1
                                                    if not serial_match:
                                                        serial_match = re.search(r"PID: .+?SN: (\S+)[\n\r]", serial_cmd_output)  # Alternative pattern 2
                                                    if not serial_match:
                                                        serial_match = re.search(r"PID: .+?SN:\s*(\S+)", serial_cmd_output)  # Alternative pattern 3

                                                    if serial_match:
                                                        device_data['Serial Number'] = serial_match.group(1)
                                                        
                                                    model_match = re.search(r"PID: \s*(\S+)", serial_cmd_output)
                                                    if model_match:
                                                        device_data['Model'] = model_match.group(1).rstrip(",")
                                            
                                            elif '9906' in device_data['Hostname']:
                                                print("DATA FOR 9906")
                                                inventory = ssh.send_command("show inventory | include 9906",read_timeout=300)
                                               
                                                serial_match = re.search(r"SN: (\S+)[\n\r]", inventory)  # Standard pattern
                                                if not serial_match:
                                                    serial_match = re.search(r"SN:\s*(\S+)", inventory)  # Alternative pattern 1
                                                if not serial_match:
                                                    serial_match = re.search(r"PID: .+?SN: (\S+)[\n\r]", inventory)  # Alternative pattern 2
                                                if not serial_match:
                                                    serial_match = re.search(r"PID: .+?SN:\s*(\S+)", inventory)  # Alternative pattern 3

                                                if serial_match:
                                                    device_data['Serial Number'] = serial_match.group(1)
                                                    
                                                model_match = re.search(r"PID: \s*(\S+)", inventory)
                                                if model_match:
                                                    device_data['Model'] = model_match.group(1).rstrip(",")
                                                    
                                                if not serial_match:
                                                    print("Executing command: admin show inventory chassis")
                                                    serial_cmd_output = ssh.send_command("admin show inventory chassis",read_timeout=300)
                                                    print(f"Output: {serial_cmd_output}")

                                                    # Updated serial number extraction to handle variations in format
                                                    serial_match = re.search(r"SN: (\S+)[\n\r]", serial_cmd_output)  # Standard pattern
                                                    if not serial_match:
                                                        serial_match = re.search(r"SN:\s*(\S+)", serial_cmd_output)  # Alternative pattern 1
                                                    if not serial_match:
                                                        serial_match = re.search(r"PID: .+?SN: (\S+)[\n\r]", serial_cmd_output)  # Alternative pattern 2
                                                    if not serial_match:
                                                        serial_match = re.search(r"PID: .+?SN:\s*(\S+)", serial_cmd_output)  # Alternative pattern 3

                                                    if serial_match:
                                                        device_data['Serial Number'] = serial_match.group(1)
                                                        
                                                    model_match = re.search(r"PID: \s*(\S+)", serial_cmd_output)
                                                    if model_match:
                                                        device_data['Model'] = model_match.group(1).rstrip(",")
                                                    
                                                    
                                             
                                                print(f"Serial Number: {device_data['Serial Number']}")
                                                print(f"Model: {device_data['Model']}")
                                          
                                            
                                            elif '9903' in device_data['Hostname']:
                                                print("DATA FOR 9903")
                                                inventory = ssh.send_command("show inventory | include ASR-9903| exclude 3- ",read_timeout=300)
                                               
                                                serial_match = re.search(r"SN: (\S+)[\n\r]", inventory)  # Standard pattern
                                                if not serial_match:
                                                    serial_match = re.search(r"SN:\s*(\S+)", inventory)  # Alternative pattern 1
                                                if not serial_match:
                                                    serial_match = re.search(r"PID: .+?SN: (\S+)[\n\r]", inventory)  # Alternative pattern 2
                                                if not serial_match:
                                                    serial_match = re.search(r"PID: .+?SN:\s*(\S+)", inventory)  # Alternative pattern 3

                                                if serial_match:
                                                    device_data['Serial Number'] = serial_match.group(1)
                                                    
                                                model_match = re.search(r"PID: \s*(\S+)", inventory)
                                                if model_match:
                                                    device_data['Model'] = model_match.group(1).rstrip(",")
                                                    
                                                if not serial_match:
                                                    print("Executing command: admin show inventory chassis")
                                                    serial_cmd_output = ssh.send_command("admin show inventory chassis",read_timeout=300)
                                                    print(f"Output: {serial_cmd_output}")

                                                    # Updated serial number extraction to handle variations in format
                                                    serial_match = re.search(r"SN: (\S+)[\n\r]", serial_cmd_output)  # Standard pattern
                                                    if not serial_match:
                                                        serial_match = re.search(r"SN:\s*(\S+)", serial_cmd_output)  # Alternative pattern 1
                                                    if not serial_match:
                                                        serial_match = re.search(r"PID: .+?SN: (\S+)[\n\r]", serial_cmd_output)  # Alternative pattern 2
                                                    if not serial_match:
                                                        serial_match = re.search(r"PID: .+?SN:\s*(\S+)", serial_cmd_output)  # Alternative pattern 3

                                                    if serial_match:
                                                        device_data['Serial Number'] = serial_match.group(1)
                                                        
                                                    model_match = re.search(r"PID: \s*(\S+)", serial_cmd_output)
                                                    if model_match:
                                                        device_data['Model'] = model_match.group(1).rstrip(",")
                                                    
                                                    
                                             
                                                print(f"Serial Number: {device_data['Serial Number']}")
                                                print(f"Model: {device_data['Model']}")
                                            
                                            
                                            
                                        elif '9904' not in device_data['Hostname'] or '9906' not in device_data['Hostname']:
                                            print("DEBUGGING")
                                            # For XR devices, retrieve serial number using "admin show inventory chassis"
                                            print("Executing command: admin show inventory chassis")
                                            serial_cmd_output = ssh.send_command("admin show inventory chassis",read_timeout=300)
                                            print(f"Output: {serial_cmd_output}")

                                            # Updated serial number extraction to handle variations in format
                                            serial_match = re.search(r"SN: (\S+)[\n\r]", serial_cmd_output)  # Standard pattern
                                            if not serial_match:
                                                serial_match = re.search(r"SN:\s*(\S+)", serial_cmd_output)  # Alternative pattern 1
                                            if not serial_match:
                                                serial_match = re.search(r"PID: .+?SN: (\S+)[\n\r]", serial_cmd_output)  # Alternative pattern 2
                                            if not serial_match:
                                                serial_match = re.search(r"PID: .+?SN:\s*(\S+)", serial_cmd_output)  # Alternative pattern 3

                                            if serial_match:
                                                device_data['Serial Number'] = serial_match.group(1)
                                                
                                            model_match = re.search(r"PID: \s*(\S+)", serial_cmd_output)
                                            if model_match:
                                                device_data['Model'] = model_match.group(1).rstrip(",")
                                         
                                            print(f"Serial Number: {device_data['Serial Number']}")
                                            print(f"Model: {device_data['Model']}")
                                            
                              
                                    interface_status = ssh.send_command("show ipv4 interface brief",read_timeout=300)
                                    gig_up = gig_down = gig_admin_down = 0
                                    ten_gig_up = ten_gig_down = ten_gig_admin_down = 0
                                    hundred_gig_up = hundred_gig_down = hundred_gig_admin_down = 0
                                    
                                    interface_lines = interface_status.splitlines()
                                    
                                    for lines in interface_lines:
                                        columns = lines.split()
                                        if "GigabitEthernet" in lines and "." not in columns[0]:
                                            if columns[2] == xr_up:
                                                gig_up += 1
                                            elif columns[2] == xr_down:
                                                gig_down += 1
                                            elif columns[2] == xr_down_down:
                                                gig_admin_down += 1
                                                
                                        elif "TenGigE" in lines and "." not in columns[0] and "nVFabric" not in columns[0]:
                                            if columns[2] == xr_up:
                                                ten_gig_up+= 1
                                            elif columns[2] == xr_down:
                                                ten_gig_down += 1
                                            elif columns[2] == xr_down_down:
                                                ten_gig_admin_down += 1
                                                
                                        elif "Hun" in lines and "." not in columns[0]:
                                            if columns[2] == xr_up:
                                                hundred_gig_up += 1
                                            elif columns[2] == xr_down:
                                                hundred_gig_down += 1
                                            elif columns[2] == xr_down_down:
                                                hundred_gig_admin_down += 1
                                    
                            
                            
                                    print("Gig interfaces:")
                                    print(f"Gig Up: {gig_up}, Gig Down: {gig_down},  Gig Admin Down: {gig_admin_down}")
                                    
                                    print("10G interfaces:")
                                    print(f"TenG Up: {ten_gig_up}, TenG Down: {ten_gig_down},  TenG Admin Down: {ten_gig_admin_down}")
                            
                                    print("100G interfaces:")
                                    print(f"100G Up: {hundred_gig_up}, 100G Down: {hundred_gig_down},  100G Admin Down: {hundred_gig_admin_down}")
                            
                            
                                    device_data['Gig_up'] = gig_up
                                    device_data['Gig_down'] = gig_down
                                    device_data['Gig_admin_down'] = gig_admin_down
                                    
                                    device_data['TenG_up'] = ten_gig_up
                                    device_data['TenG_down'] = ten_gig_down
                                    device_data['TenG_admin_down'] = ten_gig_admin_down
                                    
                                    device_data['HunG_up'] = hundred_gig_up
                                    device_data['HunG_down'] = hundred_gig_down
                                    device_data['HunG_admin_down'] = hundred_gig_admin_down
                                    
                                    device_data['Total 1G Ports'] =  device_data['Gig_up'] + device_data['Gig_down'] + device_data['Gig_admin_down'] 
                                    print(f"Total 1G Ports : {device_data['Total 1G Ports']}")
                                    
                                    device_data['Total 10G Ports'] = device_data['TenG_up'] + device_data['TenG_down'] + device_data['TenG_admin_down']
                                    print(f"Total 10G Ports : {device_data['Total 10G Ports']}")
                                    
                                    device_data['Total 100G Ports'] = device_data['HunG_up'] + device_data['HunG_down'] + device_data['HunG_admin_down']
                                    print(f"Total 100G Ports : {device_data['Total 100G Ports']}")
                                    
                                    
                                    if device_data['Total 1G Ports']  == 0:
                                       device_data['1G Utilization (%)'] = 0
                                    else:
                                        device_data['1G Utilization (%)'] = device_data['Gig_up'] / device_data['Total 1G Ports']
                                        print(f"1G Utilization {device_data['1G Utilization (%)']}")
                                        
                                    if device_data['Total 10G Ports'] == 0:
                                       device_data['10G Utilization (%)'] = 0
                                    else:
                                        device_data['10G Utilization (%)'] = device_data['TenG_up'] / device_data['Total 10G Ports']
                                        print(f"10G Utilization {device_data['10G Utilization (%)']}")
                                        
                                    if device_data['Total 100G Ports'] == 0:
                                       device_data['100G Utilization (%)'] = 0
                                       
                                    else:
                                        device_data['100G Utilization (%)'] = device_data['HunG_up'] / device_data['Total 100G Ports']
                                        print(f"100G Utilization {device_data['100G Utilization (%)']}")
                                  
                                        
                            elif version_match.group(1) == 'XE':
                            
                                if device_data['IP Address'].startswith('172.30.') or device_data['IP Address'].startswith('172.31.'):
                                    if device_data['IP Address'].endswith('.0') or device_data['IP Address'].endswith('.1'):
                                        print("TERMINATE")
                                        break
                                    isis = ssh.send_command('show isis neighbor')
                                    loopback = ssh.send_command('show ip int brief | include Loopback', read_timeout=300)
                                    
                                    if "System Id" in isis and 'Loopback' in loopback:
                                        print(f"Skipping device {device_data['IP Address']} as it has neighbors in ISIS.")
                                        print('*******************************')
                                        break
                                        
                                    else:    
                                        count_interfaces(ssh, device_data)
                                        device_data['Function'] = "AS"
                                        
                                        serial_match = re.search(r"Processor board ID (\S+)", cmd_output)
                                        if serial_match:
                                            device_data['Serial Number'] = serial_match.group(1)
                                        
                                        model_match = re.search(r"cisco (.+?) processor", cmd_output)
                                        if model_match:
                                            device_data['Model'] =re.sub(r"\s*\(.*", "", model_match.group(1))
                                        
                                        print(f"Function: {device_data['Function']}")
                                        print(f"SN: {device_data['Serial Number']}")
                                        
                                        print(f"Model: {device_data['Model']}")
                                        
                                else:
                                    count_interfaces(ssh, device_data)
                                    device_data['Function'] = "APE"
                                    
                                    serial_match = re.search(r"Processor board ID (\S+)", cmd_output)
                                    if serial_match:
                                        device_data['Serial Number'] = serial_match.group(1)
                                    
                                    model_match = re.search(r"cisco (.+?) processor", cmd_output)
                                    if model_match:
                                        device_data['Model'] =re.sub(r"\s*\(.*", "", model_match.group(1))
                                    
                                    print(f"Function: {device_data['Function']}")
                                    print(f"SN: {device_data['Serial Number']}")
                                    
                                    print(f"Model: {device_data['Model']}")
                             
                    
                        elif 'c7600rsp72043_rp' in cmd_output or 'c7600s72033_rp' in cmd_output or '7300 Software' in cmd_output:
                            # Process for c7600rsp72043_rp and c7600s72033_rp
                            
                            
                            count_interfaces(ssh, device_data) #Interface Function
                            
                            version_match_c7600rsp = re.search(r"Version (.+?),", cmd_output)
                            if version_match_c7600rsp:
                                device_data['Version'] = version_match_c7600rsp.group(1)
                                
                            serial_match = re.search(r"Processor board ID (\S+)", cmd_output)
                            if serial_match:
                                device_data['Serial Number'] = serial_match.group(1)
                                
                            model_match = re.search(r"Cisco (.+?) processor", cmd_output)
                            if not model_match:
                                model_match = re.search(r"cisco (.+?) processor", cmd_output)
                            
                            if model_match:
                                device_data['Model'] = re.sub(r"\s*\(.*", "", model_match.group(1))
                                
                            if '7300 Software' in cmd_output:
                            
                                gig_up = gig_down = gig_admin_down = 0
                                ten_gig_up = ten_gig_down = ten_gig_admin_down = 0
    
                                
                                portcount = ssh.send_command("show ip interface brief")
                                
                                portlines = portcount.splitlines()
                                
                                for interface in portlines:
                                    portcolumn = interface.split()
                                    if 'Giga' in portcolumn[0] and "." not in portcolumn[0]:
                                        
                                        if portcolumn[4].lower() == xe_up.lower():
                                            gig_up += 1
                                           
                                        elif portcolumn[4].lower() == xe_down.lower():
                                            gig_down += 1
                                        elif portcolumn[4].lower() == xe_down_down.lower():
                                            gig_admin_down += 1
                                
                                device_data['Gig_up'] = gig_up
                                device_data['Gig_down'] = gig_down
                                device_data['Gig_admin_down'] = gig_admin_down
                                    
                            print(f"SN: {device_data['Serial Number']}")
                            print(f"Version: {device_data['Version']}")
                            print(f"Model: {device_data['Model']}")
                        
                        else:
                            print("WE ARE HERE NOW")
                            count_interfaces(ssh, device_data) #interface Function
                           
                            
                            # Define a mapping between keywords and corresponding regex patterns
                            device_mapping = {
                                
                                "Nexus" : (r"kickstart: version\s*(\S+)", r"Processor Board ID (\S+)", r"(?i)cisco\s+(\S+)\s+(?:Chassis\s+)?(?:\(\".*\"\)|supervisor|Slot)"),
                                "Cisco IOS-XE software" : (r"Version (.+?),", r"Processor board ID (\S+)", r"(?i)cisco (.+?) with"),
                                "Cisco IOS Software" : (r"Version (.+?),", r"Processor board ID (\S+)", r"(?i)cisco (.+?) with"),
                                "Cisco Internetwork" : (r"Version (.+?),", r"Processor board ID (\S+)", r"cisco\s+(\d+/\S+)"),
                            }   
                       
                            for keyword, (version_pattern, serial_pattern, model_pattern) in device_mapping.items():
                                if keyword in cmd_output:
                                    # Extract version
                                    version_match = re.search(version_pattern, cmd_output)
                                    if version_match:
                                        device_data['Version'] = version_match.group(1)

                                    # Extract serial number
                                    serial_match = re.search(serial_pattern, cmd_output)
                                    if serial_match:
                                        device_data['Serial Number'] = serial_match.group(1)
                                        
                                    model_match = re.search(model_pattern, cmd_output)
                                    if model_match:
                                        device_data['Model'] = re.sub(r"\s*\(.*", "", model_match.group(1))
                                        if "3400" in device_data['Model']:
                                            if device_data['Hostname'][-1].lower() == "a":
                                                device_data['Function'] = "AS"
                                            elif device_data['Hostname'][-1].lower() == "b":
                                                device_data['Function'] = "BS"
                                                
                                elif keyword not in cmd_output:
                                    serial = ssh.send_command('show inventory',read_timeout=300)
                                    serial_cmd_output = re.search(r"Hw Serial#: (\S+)", serial)
                                    if serial_cmd_output:
                                        device_data['Serial Number'] = serial_cmd_output.group(1)
                                        
                            print(f"SN: {device_data['Serial Number']}")
                            print(f"Version: {device_data['Version']}")
                            print(f"Model: {device_data['Model']}")
                            
                               
                    else:
                        print("EXTRA COMMANDS")
                        # Extract everything after the word "show" in the command to use as the column name
                        command_column_name = cmd.split("show", 1)[1].strip()
                        # Replace spaces with underscores in the column name
                        command_column_name = command_column_name.replace(" ", "_")
                        
                        # If the column name doesn't exist in the device_data dictionary, create it
                        #if command_column_name not in device_data:
                            #device_data[command_column_name] = []

                        # Store the output of the command in the device_data dictionary
                        #device_data[command_column_name].append(cmd_output)
                        #print(f"Output of {cmd}: {cmd_output}")
                        
                        output_file.write(f"IP Address: {device}\n")
                        output_file.write(f"Command: {cmd}\n")
                        output_file.write(f"{cmd_output}\n\n")
                        
                        
        
                # Append the data to the list
                data.append(device_data)
                print(f'Closing connection to {device}')
                print('*******************************')
             

        #Error Handling    
        except NetMikoTimeoutException:
            logging.error(f'Timeout while connecting to {device}')
            print(f'Timeout while connecting to {device}')
            
        except NetMikoAuthenticationException:
            logging.error(f'Authentication failure for {device}')
            print(f"Wrong Password for {device}")
            
        except Exception as e:
            logging.error(f'An error occurred while connecting to {device}: {str(e)}')
            print(f'An error occurred while connecting to {device}: {str(e)}')    
            

# Reading devices and commands from files
with open('autodevices2.txt') as router:
    ips = router.read().splitlines()

with open('commands.txt') as command:
    commands = command.read().splitlines()

# Processing each device
for device in ips:
    
    with open("Interface Descriptions.txt", "w") as output_file:
        process_device(device, username, password, commands)
        
# Create a DataFrame from the collected data
df = pd.DataFrame(data)

# Write the DataFrame to an Excel file (without header)
excel_file = f"01 MAY Network Inventory.xlsx"
df.to_excel(excel_file, index=False)

print(f'Data has been saved to {excel_file}')

