import nftables
import re
import json
import threading
import sched
import time
import uuid

# nftools comments

# porthideinit-sometext - for init rules, such deny all traffic and allow 80 port for access requests
# porthideallow-IPv4 - for single allowed ip

DATA_FILE = 'data/allowed_addresses.json'
REQUEST_PORT = 80

nft = nftables.Nftables()
nft.set_json_output(True)
default_chain = 'INPUT'
access_time = 10 # Seconds

# Example Format: {ip: {timestamp}}
allowed_addresses = json.loads('{}')

def save():
    with open(DATA_FILE, 'w') as f:
        json.dump(allowed_addresses, f)


# Added deny rules and resore timestamps from file
def init():
    global default_chain
    
    # check filter chain
    filter_check = False
    rc, output, error = nft.cmd("list tables")
    deserialized = json.loads(output)['nftables']
    for i in deserialized:
        if 'table' in i.keys():
            if i['table']['name'] == 'filter':
                filter_check = True
                break
    if not filter_check:
        rc, output, error = nft.cmd('add table filter')
        print(f'Created new table "filter" with code {rc}"')

    
    chain_check = False
    
    rc, output, error = nft.cmd("list chains")
    deserialized = json.loads(output)['nftables']
    for i in deserialized:
        if 'chain' in i.keys():
            if i['chain']['table'] == 'filter':
                chain_check = True

                default_chain = i['chain']['name']
                break
    
    if not chain_check:
        rc, output, error = nft.cmd(f'add chain ip filter {default_chain} {{type filter hook input priority 0; policy accept;}}')
        print(f'Created new chain "{default_chain}" with code {rc}"')

    rc, output, error = nft.cmd(f'add rule ip filter {default_chain} tcp dport 31337 counter drop comment "porthideinit-denyports"')
    rc, output, error = nft.cmd(f'insert rule ip filter {default_chain} tcp dport 80 counter accept comment "porthideinit-acceptwebrequests"')
    rc, output, error = nft.cmd(f'insert rule ip filter {default_chain} iif lo accept comment "porthideinit-acceptloopback"')
    
    # load saved requests from previos run
    with open(DATA_FILE, 'r') as f:
        allowed_addresses = json.load(f)
    now = time.time()
    to_clear = []
    for i in allowed_addresses.keys():
        if allowed_addresses[i] < now:
            to_clear.append(i)
    for i in to_clear:
        del allowed_addresses[i]
    save()

    print('init complete')


# Program exit
def final(signum, frame):
    rc, output, error = nft.cmd("list ruleset")

    for i in json.loads(output)['nftables']:
        # print(i)
        if 'rule' in i.keys():
            if 'comment' in i['rule'].keys():
                comment = i['rule']['comment']
                m = re.match('porthide', comment)
                if m is not None:
                    rc, output, error = nft.cmd(f'delete rule ip filter {default_chain} handle {str(i["rule"]["handle"])}')
    print('\nall cleared\nGoodbye\n')
    exit(0)


# for threading
def schedule_remove_access(ip, timestamp):
    allowed_addresses[ip] = timestamp
    rc, output, error = nft.cmd("list ruleset")

    for i in json.loads(output)['nftables']:
        # print(i)
        if 'rule' in i.keys():
            comment = i['rule']['comment']
            m = re.match('porthideallow', comment)
            if m is not None:
                m = re.match('porthideallow-.*[^-]', comment)
                if m is not None:
                    print(m)
                    founded_ip = m[0].split('-')[1]
                    if founded_ip == ip:
                        print(f'delete rule ip filter {default_chain} handle {str(i["rule"]["handle"])}')
                        rc, output, error = nft.cmd(f'delete rule ip filter {default_chain} handle {str(i["rule"]["handle"])}')
                        del allowed_addresses[ip]
                        save()
                        print('accept rule removed')  

def request_access(ip):
    print('begin request')

    if ip in allowed_addresses.keys():
        allowed_addresses[ip] = time.time() + access_time
        print(f'updated {ip} until {allowed_addresses[ip]}')
        return

    rc, output, error = nft.cmd(f'insert rule ip filter {default_chain} ip saddr {ip} counter accept comment "porthideallow-{ip}"')
    print('accept rule added')
    allowed_addresses[ip] = time.time() + access_time
    save()

    print(f'added {ip} until {allowed_addresses[ip]}')
    scheduler = sched.scheduler(time.time, time.sleep)
    scheduler.enterabs(allowed_addresses[ip], 1, schedule_remove_access, (ip,allowed_addresses[ip],))
    threading.Thread(target=scheduler.run).start()
    # print(f'{ip} removed')