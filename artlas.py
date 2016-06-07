import re,requests,json,telepot,time,apache_log_parser
from pygtail import Pygtail
from threading import Thread
from pyzabbix import ZabbixMetric, ZabbixSender

def get_conf():
    from ConfigParser import ConfigParser
    conf = dict()
    config = ConfigParser()
    config.read('etc/artlas.conf')
    conf['api'] = config.get('Telegram','api')
    conf['group_id'] = int(config.get('Telegram','group_id'))
    conf['telegram_enable'] = config.get('Telegram','enable')
    conf['serve_name'] = config.get('Zabbix','server_name')
    conf['agentd_config'] = config.get('Zabbix','agentd_config')
    conf['zabbix_enable'] = config.get('Zabbix','enable')
    conf['apache_log'] = config.get('General','apache_log')
    conf['rules'] = config.get('General','rules')
    conf['apache_mask'] = config.get('General','apache_mask')
    conf['vhost_enable'] = config.get('General','vhost_enable')

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

def send_zabbix(msg):
    metrics = [ZabbixMetric(conf['serve_name'], 'artlas_check', 'OK')]
    ZabbixSender(use_config=conf['agentd_config']).send(metrics)
    metrics = [ZabbixMetric(conf['serve_name'], 'artlas_check', msg)]
    ZabbixSender(use_config=conf['agentd_config']).send(metrics)

def connections(linha):
    line_parser = apache_log_parser.make_parser(conf['apache_mask'])
    log = line_parser(linha)
    if conf['vhost_enable'] == 'True':
        log['vhost'] = linha.split(' ')[0]
    else:
        log['vhost'] = None
    log['owasp'] = owasp(log['request_url'])
    if log['owasp']:
        msg ='''[+] - Intrusion Attempt - [+]
Date: %s
Vhost: %s
IP: %s
Path: %s
User-Agent: %s
Browser: %s
S.O: %s
Description: %s
Impact: %s
Category: %s''' %(log['time_received'],log['vhost'],log['remote_host'],log['request_url'],
        log['request_header_user_agent'],log['request_header_user_agent__browser__family']+' '+log['request_header_user_agent__browser__version_string'],
        log['request_header_user_agent__os__family'],log['owasp']['description'],
        log['owasp']['impact'],','.join(log['owasp']['tags']['tag']))
        print msg
        print
        if conf['zabbix_enable'] == 'True':
            send_zabbix(msg)

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

rules = json.loads(open(conf['rules']).read())

while True:
    for linha in Pygtail(conf['apache_log']):
        t = Thread(target=connections, args=(linha,))
        t.start()
