import re,requests,json,telepot,time
from pygtail import Pygtail
from lxml import html
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
    conf['apache_log'] = config.get('Files','apache_log')
    conf['rules'] = config.get('Files','rules')
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
            msg = '[+] - Intrusion Attempt - [+]\nDate: '+infos['date']+'\nIP: '+infos['ip']+'\nReverse DNS: '+dados['reverse_dns']+'\nISP: '+dados['isp']+'\nPath: '+infos['path']+'\nUser-Agent: '+infos['user_agent']+'\nDescription: '+resultado['description']+'\nImpact: '+resultado['impact']+ '\nCategory: '+','.join(resultado['tags']['tag']) +'\nRegional Information'+'\nCountry:'+dados['locate']+' Region:'+dados['region']+' City:'+dados['city']
            if conf['telegram_enable'] == 'True':
                bot.sendMessage(conf['group_id'], msg)
                time.sleep(3)
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
    blacklist = list()
    data = {'ip':address}
    url = 'http://www.ipvoid.com/'
    r = requests.post(url,data=data)
    tree = html.fromstring(r.content)
    ip_infos = dict()

    ip_infos['reverse_dns'] = tree.xpath('//*[@id="left"]/table[1]/tbody/tr[4]/td[2]/text()')[0].strip()
    ip_infos['isp'] = tree.xpath('//*[@id="left"]/table[1]/tbody/tr[7]/td[2]/text()')[0].strip()

    ip_infos['locate'] = tree.xpath('//*[@id="left"]/table[1]/tbody/tr[9]/td[2]/text()')[0].strip()
    ip_infos['region'] = tree.xpath('//*[@id="left"]/table[1]/tbody/tr[12]/td[2]/text()')[0].strip()
    ip_infos['city'] = tree.xpath('//*[@id="left"]/table[1]/tbody/tr[11]/td[2]/text()')[0].strip()

    blacklist_name = tree.xpath('//*[@id="left"]/table[2]/tbody/tr/td[1]/text()')
    blacklist_status = tree.xpath('//*[@id="left"]/table[2]/tbody/tr/td[2]/img/@title')
    for x in range(0,len(blacklist_status)):
        if blacklist_status[x].strip() == 'Detected':
            blacklist.append({blacklist_name[x].strip():blacklist_status[x].strip()})
    ip_infos['blacklist'] = blacklist

    return ip_infos


conf = get_conf()
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

while True:
    for linha in Pygtail(conf['apache_log']):
        for i in range(20):
            t = Thread(target=connections, args=(linha,))
            t.start()
