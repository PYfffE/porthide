import nftables
import re
import json
import threading
import sched
import time

DATA_FILE = 'data/allowed_addresses.json'

nft = nftables.Nftables()
nft.set_json_output(True)

# Format: {ip: timestamp}
allowed_addresses = json.loads('{}')

# Added deny rules and resore timestamps from file
def init():
    rc, output, error = nft.cmd('add rule ip filter INPUT tcp dport {31337} counter drop comment "porthide-31337-drop"')
    with open(DATA_FILE, 'r') as f:
        allowed_addresses = json.load(f)
    print('init complete')

def final():
    pass

# for threading
def schedule_remove_access(ip, timestamp):
    allowed_addresses[ip] = timestamp
    rc, output, error = nft.cmd("list ruleset")


    for i in json.loads(output)['nftables']:
        # print(i)
        if 'rule' in i.keys():
            comment = i['rule']['comment']
            m = re.match('porthide.*accept', comment)
            if m is not None:
                m = re.match('porthide-.*[^-]', comment)
                if m is not None:
                    print(m)
                    founded_ip = m[0].split('-')[1]
                    print(f'delete rule ip filter INPUT handle {str(i["rule"]["handle"])}"')
                    if founded_ip == ip:
                        rc, output, error = nft.cmd(f'delete rule ip filter INPUT handle {str(i["rule"]["handle"])}')
                        print('accept rule removed')
            

    with open(DATA_FILE, 'w') as f:
        json.dump(allowed_addresses, f)

def request_access(ip):
    print('begin request')

    rc, output, error = nft.cmd(f'insert rule ip filter INPUT tcp dport {31337} counter accept comment "porthide-{ip}-31337-accept"')

    print('accept rule added')
    allowed_addresses[ip] = time.time() + 10
    with open(DATA_FILE, 'w') as f:
        json.dump(allowed_addresses,f)

    print(f'added {ip} for {allowed_addresses[ip]}')
    scheduler = sched.scheduler(time.time, time.sleep)
    scheduler.enterabs(allowed_addresses[ip], 1, schedule_remove_access, (ip,allowed_addresses[ip],))
    scheduler.run()
    # print(f'{ip} removed')


# init()
# request_access('1.1.1.1')


