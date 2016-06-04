import re,requests,json,telepot,time,apache_log_parser
from pygtail import Pygtail
from pyzabbix import ZabbixAPI
from threading import Thread

def get_conf():
    from ConfigParser import ConfigParser
    conf = dict()
    config = ConfigParser()
    config.read('etc/artlas.conf')
    conf['api'] = config.get('Telegram','api')
    conf['group_id'] = int(config.get('Telegram','group_id'))
    conf['telegram_enable'] = config.get('Telegram','enable')
    conf['username'] = config.get('Zabbix','username')
    conf['password'] = config.get('Zabbix','password')
    conf['server'] = config.get('Zabbix','server')
    conf['zabbix_enable'] = config.get('Zabbix','enable')
    conf['apache_log'] = config.get('General','apache_log')
    conf['rules'] = config.get('General','rules')
    conf['apache_mask'] = config.get('General','apache_mask')
    return conf

def get_file_rules():
    r = requests.get('http://dev.itratos.de/projects/php-ids/repository/raw/trunk/lib/IDS/default_filter.json')
    with open('etc/default_filter.json','w') as file_rules:
        file_rules.write(r.content)
        file_rules.close()


def owasp(path):
    for filtro in rules['filters']['filter']:
        try:
            if re.search(filtro['rule'], path):
                return filtro
        except:
            pass

def connections(linha):
    line_parser = apache_log_parser.make_parser(conf['apache_mask'])
    log = line_parser(linha)
    log['owasp'] = owasp(log['request_url'])
    if log['owasp']:
        msg ='''[+] - Intrusion Attempt - [+]
Date: %s
IP: %s
Path: %s
User-Agent: %s
Browser: %s
S.O: %s
Description: %s
Impact: %s
Category: %s''' %(log['time_received'],log['remote_host'],log['request_url'],
        log['request_header_user_agent'],log['request_header_user_agent__browser__family']+' '+log['request_header_user_agent__browser__version_string'],
        log['request_header_user_agent__os__family'],log['owasp']['description'],
        log['owasp']['impact'],','.join(log['owasp']['tags']['tag']))
        print msg
        print
        if conf['telegram_enable'] == 'True':
            time.sleep(3)
            bot.sendMessage(conf['group_id'], msg)

print '[+] - Getting configs'
conf = get_conf()
print 'Done!\n'

print '[+] - Getting rules file'
get_file_rules()
print 'Done!\n'

print 'A.R.T.L.A.S Started!\n'

#Check Telegram enabled
if conf['telegram_enable'] == 'True':
    bot = telepot.Bot(conf['api'])
    print '[+] - Telegram Enabled'

#Check Zabbix enabled
if conf['zabbix_enable'] == 'True':
    zapi = ZabbixAPI(server)
    zapi.login(conf['username'], conf['password'])
    print '[+] - Zabbix Enabled'

rules = json.loads(open(conf['rules']).read())

while True:
    for linha in Pygtail(conf['apache_log']):
        t = Thread(target=connections, args=(linha,))
        t.start()
