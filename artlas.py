import xmltodict,sys,re,requests,json,telepot
from pygtail import Pygtail
from lxml import html

def connections(line):
        infos = {}
        line = line.split('"')
        infos['ip'] = line[0].split(' ')[0]
        infos['method'] = line[1].split(' ')[0]
        infos['path'] = line[1].split(' ')[1]
        infos['status_code'] = line[2].split(' ')[1]
        infos['user_agent'] = line[5]


        resultado = owasp(infos['path'])
        if resultado:
            dados = ipinfos(infos['ip'])
            print '[+] - Vulneravel - [+]'
            print 'IP:',infos['ip']
            print 'Reverse DNS:',dados['reverse_dns']
            print 'Provedor:',dados['isp']
            print 'Path:',infos['path']
            print 'Descricao:',resultado['description']
            print 'Gravidade:',resultado['impact']
            print 'Informacoes Regionais'
            print dados['locate'],dados['region'],dados['city']
            print 'Blacklist: ',dados['blacklist'] if dados['blacklist'] else 'Clean'
            #bot.sendMessage(group_id, 'ID: '+h['hostid']+'\nStatus: '+status+'\nHost: '+h['host']+'\nNome: '+h['name'])
            print

def owasp(path):
    for filtro in regras['filters']['filter']:
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

def main():
    while True:
        for linha in Pygtail(log_file):
            connections(linha)

log_file = '/Users/matheusbernardes/MEGAsync/OSINT/ARTLAS/access.log'
log_file_p = open(log_file,'r')
f = open('default_filter.xml').read()
regras = xmltodict.parse(f,process_namespaces=True)
main()
