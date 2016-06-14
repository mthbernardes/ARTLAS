import syslog_client as syslog
import re
import requests
import json
import telepot
from time import sleep
import apache_log_parser
from pygtail import Pygtail
from threading import Thread
from pyzabbix import ZabbixMetric, ZabbixSender
from ConfigParser import ConfigParser

class ARTLAS(object):

	def __init__(self, config_file):

		print('[*] Getting config...')
		self.conf = dict()
		self.get_conf(config_file)
		print('[+] Done!\n')

		# Check if CEF_Syslog is enabled
		if self.conf['cef_syslog_enable']:
			print '[+] Syslog Enabled'
			self.syslog = syslog.Syslog(self.conf['cef_syslog_server'])

		# Check if Telegram is enabled
		if self.conf['telegram_enable']:
			print '[+] Telegram Enabled'
			self.bot = telepot.Bot(self.conf['api'])

		# Check if Zabbix is enabled
		if self.conf['zabbix_enable']:
			print '[+] Zabbix Enabled'
			print 'Notifications ',self.conf['notifications']
			print 'Advanced ',self.conf['zabbix_advantage_keys']
		print 

		print('[*] Getting rules...')
		self.get_file_rules()
		print('[+] Done!\n')

		self.rules = json.loads(open(self.conf['rules']).read())

		# List of all senders, enabled or not
		self.senders = [self.send_zabbix, self.send_cef_syslog, self.send_telegram]


		print('[*] A.R.T.L.A.S Started!\n')

	def get_conf(self, config_file):
		config = ConfigParser()
		config.read(config_file)

		# Telegram
		self.conf['api'] = config.get('Telegram','api')
		self.conf['group_id'] = int(config.get('Telegram','group_id'))
		# One should use getboolean to fetch boolean values, otherwise they will always be True unless empty
		self.conf['telegram_enable'] = config.getboolean('Telegram','enable')

		# Zabbix
		self.conf['server_name'] = config.get('Zabbix','server_name')
		self.conf['agentd_config'] = config.get('Zabbix','agentd_config')
		self.conf['zabbix_advantage_keys'] = config.getboolean('Zabbix','enable_advantage_keys')
		self.conf['notifications'] = config.getboolean('Zabbix','notifications')
		self.conf['zabbix_enable'] = config.getboolean('Zabbix','enable')

		# Apache
		self.conf['apache_log'] = config.get('General','apache_log')
		self.conf['rules'] = config.get('General','rules')
		self.conf['apache_mask'] = config.get('General','apache_mask')
		self.conf['vhost_enable'] = config.getboolean('General','vhost_enable')

		# CEF_Syslog
		self.conf['cef_syslog_enable'] = config.getboolean('CEF_Syslog','enable')
		self.conf['cef_syslog_server'] = config.get('CEF_Syslog','server_name')

		return self.conf

	def get_file_rules(self):
		r = requests.get('http://dev.itratos.de/projects/php-ids/repository/raw/trunk/lib/IDS/default_filter.json')
		with open('etc/default_filter.json','w') as file_rules:
			file_rules.write(r.content)
			file_rules.close()

	def owasp(self, path):
		for filtro in self.rules['filters']['filter']:
			try:
				if re.search(filtro['rule'], path):
					return filtro
			except:
				continue

	def send_zabbix(self, log):
		if self.conf['zabbix_enable']:
			msg = self.verbose_format(log)
			impact = int(log['owasp']['impact'])
			allowed_range = range(1,8)
		
			if self.conf['zabbix_advantage_keys']:
				metrics = [ZabbixMetric(self.conf['server_name'], 'artlas_check{}'.format('_0{}'.format(impact) if impact in allowed_range else ''), msg)]
			else:
				metrics = [ZabbixMetric(self.conf['server_name'], 'artlas_check',msg)]
			ZabbixSender(use_config=self.conf['agentd_config']).send(metrics)
		
			if self.conf['notifications']:
				if self.conf['zabbix_advantage_keys']:
					metrics = [ZabbixMetric(self.conf['server_name'], 'artlas_check{}'.format('_0{}'.format(impact) if impact in allowed_range else ''), msg)]
				else:
					metrics = [ZabbixMetric(self.conf['server_name'], 'artlas_check',"OK")]
				ZabbixSender(use_config=self.conf['agentd_config']).send(metrics)
				
	def send_cef_syslog(self, log):
		if self.conf['cef_syslog_enable']:
			msg = self.cef_format(log)
			self.syslog.warn(msg)

	def send_telegram(self, log):
		if self.conf['telegram_enable']:
			msg = self.verbose_format(log)
			sleep(3)
			self.bot.sendMessage(self.conf['group_id'], msg)

	def send_all(self, log):
		print(self.verbose_format(log))
		for sender in self.senders:
			sender(log)


	def verbose_format(self, log):
			msg ='''[+] - Intrusion Attempt - [+]
	Date: {cef_date}
	Vhost: {vhost}
	IP: {remote_host}
	Path: {request_url}
	User-Agent: {request_header_user_agent}
	Browser: {request_header_user_agent__browser__family} {request_header_user_agent__browser__version_string}
	S.O: {request_header_user_agent__os__family}
	Description: {owasp_description}
	Impact: {owasp_impact}
	Category: {owasp_category}'''.format(owasp_description=log['owasp']['description'], owasp_impact=log['owasp']['impact'], owasp_category=','.join(log['owasp']['tags']['tag']), **log)
			return msg

	def cef_format(self, log):

			msg = 'CEF:0|ARTLAS|ARTLAS|1.0|INTRUSION_ATTEMPT|Intrusion Attempt|{owasp_impact}|end={cef_date} cs1={vhost} cs1Label=Vhost src={remote_host}\
 request={request_url} requestClientApplication="{request_header_user_agent__browser__family} {request_header_user_agent__os__family} {request_header_user_agent__browser__version_string}"\
 message={owasp_description} cs2={owasp_category} cs2Label=Category'.format(owasp_description=log['owasp']['description'], owasp_impact=log['owasp']['impact'], owasp_category=','.join(log['owasp']['tags']['tag']), **log)

			return msg


	def connections(self, linha):
		try:
			line_parser = apache_log_parser.make_parser(self.conf['apache_mask'])
			log = line_parser(linha)
			if self.conf['vhost_enable']:
				log['vhost'] = linha.split(' ')[0]
			else:
				log['vhost'] = None
			log['owasp'] = self.owasp(log['request_url'])
			if log['owasp']:
				log['cef_date'] = log['time_received_datetimeobj'].strftime('%b %d %Y %H:%M:%S')
				self.send_all(log)
		except:
			pass


	def run(self):
		while True:
			try:
				for linha in Pygtail(self.conf['apache_log']):
					t = Thread(target=self.connections, args=(linha,))
					t.start()
				# Prevent processing overflow
			except IOError:
				print('[-] Log not found: {}, waiting...'.format(self.conf['apache_log']))
				sleep(5)
			except:
				pass
			finally:
				sleep(0.01)


if __name__ == '__main__':
	artlas = ARTLAS('etc/artlas.conf')
	artlas.run()
