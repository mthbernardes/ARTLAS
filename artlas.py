import re,requests,json,telepot,time
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
    conf['threads'] = int(config.get('General','threads'))
    return conf

def get_file_rules():
    r = requests.get('https://dev.itratos.de/projects/php-ids/repository/raw/trunk/lib/IDS/default_filter.json', verify=False)
    with open('etc/default_filter.json','w') as file_rules:
        file_rules.write(r.content)
        file_rules.close()

def connections(line):
        infos = dict()
        line = line.split('"')
        infos['ip'] = line[0].split(' ')[0]
        infos['date'] = line[0].split(' ')[3].replace('[','')
        infos['method'] = line[1].split(' ')[0]
        infos['path'] = line[1].split(' ')[1]
        infos['status_code'] = line[2].split(' ')[1]
        infos['user_agent'] = line[5]
        resultado = owasp(infos['path'])
        if resultado:
            dados = ipinfos(infos['ip'])
            msg = '[+] - Intrusion Attempt - [+]\nDate: '+infos['date']+'\nIP: '+infos['ip']+'\nLong: '+dados['longitude']+'\nLag: '+dados['latitude']+'\nPath: '+infos['path']+'\nUser-Agent: '+infos['user_agent']+'\nDescription: '+resultado['description']+'\nImpact: '+resultado['impact']+ '\nCategory: '+','.join(resultado['tags']['tag']) +'\nRegional Information'+'\nCountry:'+dados['country']+' Region:'+dados['region']+' City:'+dados['city']
            if conf['telegram_enable'] == 'True':
                time.sleep(3)
                bot.sendMessage(conf['group_id'], msg)
            print msg
            print

def owasp(path):
    for filtro in rules['filters']['filter']:
        try:
            if re.search(filtro['rule'], path):
                return filtro
        except:
            pass

def ipinfos(address):
    r = requests.get('http://freegeoip.net/json/'+address)
    response = r.json()

    ip_infos = dict()
    ip_infos['latitude'] = str(response['latitude'])
    ip_infos['longitude'] = str(response['longitude'])
    ip_infos['country'] = response['country_name']
    ip_infos['region'] = response['region_name']
    ip_infos['city'] = response['city']

    return ip_infos


print '[+] - Getting configs'
conf = get_conf()
print 'Done!\n'
print '[+] - Getting rules file'
get_file_rules()

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

print 'Done!\n'
print 'Starting...'
while True:
    for linha in Pygtail(conf['apache_log']):
        for i in range(conf['threads']):
            t = Thread(target=connections, args=(linha,))
            t.start()
