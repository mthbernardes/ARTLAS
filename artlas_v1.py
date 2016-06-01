import xmltodict,sys,re,requests,json,telepot
from pygtail import Pygtail
from lxml import html
from pyzabbix import ZabbixAPI

def get_user_agent(user_agent):
    url = 'http://www.useragentstring.com/?uas='+user_agent+'&getJSON=all'
    r = requests.get(url)
    user_agent = json.loads(r.content)
    return user_agent['agent_name']

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

def connections(line):
        infos = dict()
        line = line.split('"')
        infos['ip'] = line[0].split(' ')[0]
        infos['method'] = line[1].split(' ')[0]
        infos['path'] = line[1].split(' ')[1]
        infos['status_code'] = line[2].split(' ')[1]
        infos['user_agent'] = line[5]
        resultado = owasp(infos['path'])
        if resultado:
            dados = ipinfos(infos['ip'])
            msg = '[+] - Intrusion Attempt - [+]\nIP:'+infos['ip']+'\nReverse DNS:'+dados['reverse_dns']+'\nISP:'+dados['isp']+'\nPath:'+infos['path']+'\nUser-Agent:'+get_user_agent(infos['user_agent'])+'\nDescription:'+resultado['description']+'\nImpact:'+resultado['impact']+'\nRegional Information'+'\nCountry:'+dados['locate']+' Region:'+dados['region']+' City:'+dados['city']
            if conf['telegram_enable'] == 'True':
                bot.sendMessage(conf['group_id'], msg)
            print msg
            print

def owasp(path):
    for filtro in rules['filters']['filter']:
        if re.search(filtro['rule'], path):
            return filtro

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

#Check Telegram enabled
if conf['telegram_enable'] == 'True':
    bot = telepot.Bot(conf['api'])
    print '[+] - Telegram Enabled'

#Check Zabbix enabled
if conf['zabbix_enable'] == 'True':
    zapi = ZabbixAPI(server)
    zapi.login(username, password)
    print '[+] - Zabbix Enabled'

rules = json.loads(open(conf['rules']).read())

while True:
    for linha in Pygtail(conf['apache_log']):
        connections(linha)
