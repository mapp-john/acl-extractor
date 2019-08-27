import os
import re
import json
import time
import jinja2
import socket
import random
import logging
import netmiko
import paramiko
from threading import Thread
import subprocess
import traceback
import queue as queue
from datetime import datetime
from zipfile import ZipFile, ZIP_DEFLATED
from EmailModule import emailHTMLWithRenamedAttachment

def get_firewall_policies(connection, output):
    temp_list = []
    date = str(datetime.now().ctime())
    # Show Access-lists and exclude trash lines
    temp_string = connection.send_command_timing('show access-list | exclude \d*\s*elements|alert-interval 300|access-list cached ACL log flows:')
    for line in temp_string.strip().splitlines():
        line = line.strip()
        
        # Instantiate variables
        entry = None
        policy_name = None
        position = 0
        hit_count = 0
        ID = None
        action = None
        acl_type = None
        protocol = None
        service_object = None
        src_net_object = None
        dst_net_object = None
        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        
        try:
            # Search for EtherType ACL
            if line.split()[2] == 'ethertype':
                policy_name = line.split()[1]
                acl_type = 'ethertype'
                action = line.split()[3]      
                protocol = line.split()[4]
                hit_count = line.split()[-1].replace('(hitcount=','').replace(')','')
                entry = {
                        'position': None,
                        'hit_count': hit_count,
                        'id': None,
                        'acl_type': acl_type,
                        'action': action,
                        'service_object': None,
                        'protocol': protocol,
                        'src_net_object': None,
                        'dst_net_object': None,
                        'src_ip': None,
                        'dst_ip': None,
                        'src_port': None,
                        'dst_port': None
                        }
            # Search for remarks
            elif re.search('access-list\s*(\S*)\s*line\s*(\d*)\s*remark\s*((\S*\s*)*)', line):
                regex_search = re.search('access-list\s*(\S*)\s*line\s*(\d*)\s*remark\s*((\S*\s*)*)', line)
                policy_name = regex_search.group(1)
                position = regex_search.group(2)
                remark = regex_search.group(3)
                entry = {
                        'position': position,
                        'remark': remark
                        }
            # Search for IP Any Any
            elif re.search('access-list\s*(\S*)\s*line\s*(\d*)\s*(standard|extended)\s*(\S*)\s*ip (any6|any4|any) (any6|any4|any)\s*(\w*\s*)*(\(hitcnt=(\d*)\)\s*?)?\s*(0x.*$)?',line):
                regex_search = re.search('access-list\s*(\S*)\s*line\s*(\d*)\s*(standard|extended)\s*(\S*)\s*ip (any6|any4|any) (any6|any4|any)\s*(\w*\s*)*(\(hitcnt=(\d*)\)\s*?)?\s*(0x.*$)?',line)
                policy_name = regex_search.group(1)
                position = regex_search.group(2)
                acl_type = regex_search.group(3)
                action = regex_search.group(4)
                protocol = 'ip'
                src_ip = regex_search.group(1)
                dst_ip = regex_search.group(1)
                # Assign hit_count (hitcnt=41489)
                if regex_search.group(8):
                    hit_count = regex_search.group(9)
                # Assign Rule ID  0xfdf3a6a6
                if regex_search.group(10):
                    ID = regex_search.group(10)
            # Search for all other ACLs
            elif re.search('access-list\s*(\S*)\s*line\s*(\d*)\s*(standard|extended)\s*(\S*)\s*(tcp|udp|ip|icmp|gre|esp|eigrp|(object-group|object))\s*(\S*)', line):
                regex_search = re.search('access-list\s*(\S*)\s*line\s*(\d*)\s*(standard|extended)\s*(\S*)\s*(tcp|udp|ip|icmp|gre|esp|eigrp|(object-group|object))\s*(\S*)', line)
                policy_name = regex_search.group(1)
                position = regex_search.group(2)
                acl_type = regex_search.group(3)
                action = regex_search.group(4)
                protocol = regex_search.group(5).strip()
                if regex_search.group(6):
                    service_object = regex_search.group(7)
                # Search for Source Object or IP starting from service object or protocol
                if service_object:
                    regex_search = re.search(fr'{service_object}\s*((((object-group|object)|host)\s*(\S*))|(\s*((\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\s*){{2}}))|(any6|any4|any))',line)
                else:
                    regex_search = re.search(fr'{protocol}\s*((((object-group|object)|host)\s*(\S*))|(\s*((\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\s*){{2}}))|(any6|any4|any))',line)
                if regex_search:
                    if regex_search.group(4):
                        src_net_object = regex_search.group(5)
                    elif regex_search.group(3):
                        src_ip = regex_search.group(5)
                    elif regex_search.group(1):
                        src_ip = regex_search.group(1).strip()
# =============================================================================
#                     # Test Print
#                     print(line)
#                     for i in range(len(regex_search.groups())):
#                         print(f'Index: {i+1}, Value: {regex_search.group(i+1)}')
# =============================================================================
                else:
                    entry = {'error': f'Unable to find Source Object: {line}\nDevice: {output["hostname"]}, {output["ip_address"]}\nProtocol: {protocol}\nService Object: {service_object}\n'}
                    print(entry['error'])                           
                # search for destination network objects starting from source
                if src_ip:
                    regex_search = re.search(fr'({src_ip}\s*((eq\s(\S*)|gt\s(\S*)|range\s(\S*)\s*(\S*))(?!object-group|object|host)\s*)?\s*((((object-group|object)|host)\s*(\S*))|(\s*((\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\s*){{2}}))|(any6|any4|any))\s*((eq\s(\S*)|gt\s(\S*)|range\s(\S*)\s*(\S*))(?!object-group|object|host)\s*)?)(\w*\s*)*(\(hitcnt=(\d*)\)\s*?)?\s*(0x.*$)?',line)
                else:
                    regex_search = re.search(fr'({src_net_object}\s*((eq\s(\S*)|gt\s(\S*)|range\s(\S*)\s*(\S*))(?!object-group|object|host)\s*)?\s*((((object-group|object)|host)\s*(\S*))|(\s*((\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\s*){{2}}))|(any6|any4|any))\s*((eq\s(\S*)|gt\s(\S*)|range\s(\S*)\s*(\S*))(?!object-group|object|host)\s*)?)(\w*\s*)*(\(hitcnt=(\d*)\)\s*?)?\s*(\s*0x.*$)?',line)
                if regex_search:
                    # Assign src_port
                    if regex_search.group(3) and regex_search.group(4):
                        src_port = regex_search.group(4)
                    elif regex_search.group(3) and regex_search.group(5):
                        src_port = f'gt {regex_search.group(5)}'
                    elif regex_search.group(3) and (regex_search.group(6) and regex_search.group(7)):
                        src_port = f'range {regex_search.group(6)},{regex_search.group(7)}'
                    # Assign dst_net_object
                    if regex_search.group(11):
                        dst_net_object = regex_search.group(12)
                    elif regex_search.group(10):
                        dst_ip = regex_search.group(12)
                    elif regex_search.group(13):
                        dst_ip = regex_search.group(13)
                    elif regex_search.group(16):
                        dst_ip = regex_search.group(16).strip()
                    # Assign dst_port
                    if regex_search.group(18) and regex_search.group(19):
                        dst_port = regex_search.group(19)
                    elif regex_search.group(18) and regex_search.group(20):
                        dst_port = f'gt {regex_search.group(20)}'
                    elif regex_search.group(18) and (regex_search.group(21) and regex_search.group(22)):
                        dst_port = f'range {regex_search.group(21)},{regex_search.group(22)}'
                    # Assign hit_count (hitcnt=41489)
                    if regex_search.group(24):
                        hit_count = regex_search.group(25)
                    # Assign Rule ID  0xfdf3a6a6
                    if regex_search.group(26):
                        ID = regex_search.group(26)
# =============================================================================
#                     # Test Print
#                     print(line)
#                     for i in range(len(regex_search.groups())):
#                         print(f'Index: {i+1}, Value: {regex_search.group(i+1)}')
# =============================================================================
                else:
                    entry = {'error': f'Unable to find Destination Object: {line}\nDevice: {output["hostname"]}, {output["ip_address"]}\nProtocol: {protocol}\nService Object: {service_object}\nSource IP: {src_ip}\nSource Net Object: {src_net_object}\n'}
                    print(entry['error'])
            else:
                entry = {'error': f'Does not match REGEX but begins with access-list: {line}\nDevice: {output["hostname"]}, {output["ip_address"]}\n'} 
                print(entry['error'])
        except:
            entry = {'error': f'Exception: {line}\nDevice: {output["hostname"]}, {output["ip_address"]}\n{traceback.format_exc()}'} 
            print(entry['error'])
            
        # If an entry exists
        if entry:
            try:
                output['firewall_policies'][policy_name]['entries'].append(entry)
            except KeyError:
                output['firewall_policies'][policy_name] = {'date':date,'interface':None,'direction':None,'entries': []}
                output['firewall_policies'][policy_name]['entries'].append(entry)
            except:
                print(f'Failed to append details for entry: {json.dumps(entry, indent=4)}\nDevice: {output["hostname"]}, {output["ip_address"]}\n{traceback.format_exc()}')
        # If RegEx searches succeeded
        elif dst_ip or dst_net_object:
            # Append entry to Policy Dict
            try:
                entry = {
                        'position': int(position),
                        'hit_count': int(hit_count),
                        'id': ID,
                        'acl_type': acl_type,
                        'action': action,
                        'service_object': service_object,
                        'protocol': protocol,
                        'src_net_object': src_net_object,
                        'dst_net_object': dst_net_object,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        }
                output['firewall_policies'][policy_name]['entries'].append(entry)
            except KeyError:
                output['firewall_policies'][policy_name] = {'date':date,'interface':None,'direction':None,'entries': []}
                output['firewall_policies'][policy_name]['entries'].append(entry)
            except:
                print(f'Failed to append details for entry: {json.dumps(entry, indent=4)}\nDevice: {output["hostname"]}, {output["ip_address"]}\n{traceback.format_exc()}')
    
    
    temp_string = connection.send_command('show run access-group')
    for line in temp_string.strip().splitlines():
        interface = None
        direction = None
        policy_name = None
        if line.split()[2] == 'global':
            policy_name = line.split()[1]
            interface = 'global'
            direction = 'global'
        else:
            policy_name = line.split()[1]
            interface = line.split()[-1]
            direction = line.split()[2]
        
        try:
            output['firewall_policies'][policy_name]['interface'] = interface
            output['firewall_policies'][policy_name]['direction'] = direction
        except:
            print(f'Failed to append details for access-group: {line}\nDevice: {output["hostname"]}, {output["ip_address"]}\n{traceback.format_exc()}')
            
    return output


def COMMANDS(username,password,counter,device_type,devices,deviceList,outputList):
    """
    Designed for Cisco ASA
    
    Example output:
    {
        'hostname': '',
        'ip_address': '',
        'uptime': '',
        'firewall_policies': {
            'acl-in': { 
                'interface': 'INSIDE',
                'direction': 'in',
                'date': 'Wed Aug 21 23:22:10 2019',
                'entries':    [
                    {
                        'position': 1,
                        'remark': 'CSM_SECTION_START'
                    },
                    {
                        'position': 2,
                        'acl_type': acl_type,
                        'action': 'deny',
                        'service_object': None,
                        'protocol': 'tcp',
                        'src_net_object': None,
                        'dst_net_object': None,
                        'src_ip': 'any4',
                        'dst_ip': 'any4',
                        'src_port': None,
                        'dst_port': 'pop3',
                        'hit_count': 0,
                        'id': '0x095eb91e',
                    }
                ]        
        }
    }
    """
    while not deviceList.empty():
        device = deviceList.get_nowait()
        output = {}
        try:
            # Connection Break
            counter = len(devices)-deviceList.qsize()
            print(f'[{str(counter)}] Connecting to {device}')
            # Connection Handler
            connection = netmiko.ConnectHandler(ip=device, device_type=device_type, username=username, password=password, secret=password, global_delay_factor=10)
            # Performing nslookup on device name
            if re.match(r'\b((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b',device):
                ip_address = device
                try:
                    hostname = socket.gethostbyaddr(device)[0]
                except:
                    # Hostname
                    show_output = connection.send_command('sh run hostname').strip()
                    hostname = show_output.split()[-1]
                    # Domain
                    show_output = connection.send_command('sh run domain').strip()
                    domain = show_output.split()[-1]
                    if not domain == None: 
                        hostname = f'{hostname}.{domain}'
            else:
                hostname = device
                try:
                    ip_address = socket.getaddrinfo(device,0,0,0,0)[-1][-1][0]
                except:
                    ip_address = 'NONE'
            show_output = connection.send_command('sh ver | in up').strip()
            for line in show_output.splitlines():
                if line.split()[1] == 'up':
                    uptime = line.split('up')[-1].strip()
            
            output['hostname'] = hostname
            output['ip_address'] = ip_address
            output['uptime'] = uptime
            output['firewall_policies'] = {}
            
            # Run RegEx function
            output = get_firewall_policies(connection, output)
            connection.disconnect()
            
            outputList.put(output)
            #print(json.dumps(json.loads(json.dumps(output)),indent=4))

        except:    # exceptions as exceptionOccured:
            outputList.put(f'\n!\n[{str(counter)}] CONNECTIVITY: CONNECTION ERROR - {device}\n!\n!\n{traceback.format_exc()}')
            traceback.print_exc()
    outputList.put(None)
    return

def script(form,configSettings):
    # Pull variables from web form
    devices = form['devices'].strip().splitlines()
    username = form['username']
    password = form['password']
    email = form['email']

    # Netmiko Device Type
    device_type = 'cisco_asa'


    # Define Threading Queues
    NUM_THREADS = 200
    deviceList = queue.Queue()
    outputList = queue.Queue()

    if len(devices) < NUM_THREADS:
        NUM_THREADS = len(devices)
    for line in devices:
        deviceList.put(line.strip())


    counter = 0

    # loop for devices
    for i in range(NUM_THREADS):
        Thread(target=COMMANDS, args=(username,password,counter,device_type,devices,deviceList,outputList)).start()
        time.sleep(1)

    # Random Generated Output File
    outputFileName = ''
    for i in range(6):
        outputFileName += chr(random.randint(97,122))
    outputFileName += '.txt'
    # Random Generated JSON Output File
    outputFileName_json = ''
    for i in range(6):
        outputFileName_json += chr(random.randint(97,122))
    outputFileName_json += '.txt'
    
    jsonOutput = []
    
    # Open file and write the outputList data
    with open(outputFileName,'w') as outputFile:
        outputFile.write('Hostname,IP,Uptime,Policy Name,Interface,Direction,Line Number,ACL Type,Protocol,Action,Service Object,Source Net Object,Dest Net Object,Source IP,Dest IP,Source Port,Dest Port,Hit Count,Rule ID,Discovery Time\n')
        numDone = 0
        while numDone < NUM_THREADS:
            result = outputList.get()
            if result is None:
                numDone += 1
            else:
                for policy_name in result['firewall_policies'].keys():
                    for entry in result['firewall_policies'][policy_name]['entries']:
                        # Test Print
                        #print(json.dumps(entry,indent=4))
                        if 'error' in entry.keys():
                            pass
                        elif 'remark' in entry.keys():
                            outputFile.write(f'{result["hostname"]},{result["ip_address"]},{result["uptime"]},{policy_name},{result["firewall_policies"][policy_name]["interface"]},{result["firewall_policies"][policy_name]["direction"]},{entry["position"]},remark,{entry["remark"]},None,None,None,None,None,None,None,None,None,None,{result["firewall_policies"][policy_name]["date"]}\n')
                        else:
                            outputFile.write(f'{result["hostname"]},{result["ip_address"]},{result["uptime"]},{policy_name},{result["firewall_policies"][policy_name]["interface"]},{result["firewall_policies"][policy_name]["direction"]},{entry["position"]},{entry["acl_type"]},{entry["protocol"]},{entry["action"]},{entry["service_object"]},{entry["src_net_object"]},{entry["dst_net_object"]},{entry["src_ip"]},{entry["dst_ip"]},{entry["src_port"]},{entry["dst_port"]},{entry["hit_count"]},{entry["id"]},{result["firewall_policies"][policy_name]["date"]}\n')
                jsonOutput.append(result)
    
    # Write JSON output to file
    with open(outputFileName_json,'w') as outputFile:
        outputFile.write(json.dumps(json.loads(json.dumps(jsonOutput)),indent=4))

    # ZIP Output File
    ZipFileName = outputFileName.replace('.txt','.zip')
    with ZipFile(ZipFileName,'w',ZIP_DEFLATED) as zf:
        # Writes Output File file and renames file
        zf.write(outputFileName,'results.csv')
        zf.write(outputFileName_json,'results.json')

    ##############################
    # Email Out Result
    #
    subject = 'Results for ACL Extractor'
    html = """
    <html>
    <body>
    <h1>Output from ACL Extractor </h1>
    </body>
    </html>
    """
    attachmentfile = ZipFileName
    attachmentname = 'results.zip'
    #
    From = 'ACL Extractor <ACL_Extractor@domain.com>'
    #
    emailHTMLWithRenamedAttachment(email,subject,html,attachmentfile,attachmentname,From)

    os.remove(ZipFileName)
    os.remove(outputFileName)
    os.remove(outputFileName_json)

    return
