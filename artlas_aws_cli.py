# -*- coding: utf-8 -*-
import syslog_client as syslog
import re
import requests
import json
import sys
import telepot
import subprocess
import shlex
import os
import apache_log_parser
from time import sleep
from pygtail import Pygtail
from threading import Thread
from pyzabbix import ZabbixMetric, ZabbixSender
from datetime import datetime, timezone, timedelta
try:
	from ConfigParser import ConfigParser
except:
	from configparser import ConfigParser

class ARTLAS(object):

	def __init__(self, config_file):

		print('[*] Getting config...')
		self.conf = dict()
		self.get_conf(config_file)
		print('[+] Done!\n')

		# Check if CEF_Syslog is enabled
		if self.conf['cef_syslog_enable']:
			print('[+] Syslog Enabled')
			self.syslog = syslog.Syslog(self.conf['cef_syslog_server'])

		# Check if Telegram is enabled
		if self.conf['telegram_enable']:
			print('[+] Telegram Enabled')
			self.bot = telepot.Bot(self.conf['api'])

		# Check if Slack is enabled
		if self.conf['slack_enable']:
			print('[+] Slack Enabled')

		# Check if Zabbix is enabled
		if self.conf['zabbix_enable']:
			print('[+] Zabbix Enabled')
			print('Notifications ',self.conf['notifications'])
			print('Advanced ',self.conf['zabbix_advantage_keys'])
		print() 

		print('[*] Getting rules...')
		self.get_file_rules()
		print('[+] Done!\n')

		self.rules = json.loads(open(self.conf['rules']).read())
		self.white_rules = open(self.conf['whitelist']).read().strip().split(',')

		# List of all senders, enabled or not
		self.senders = [self.send_zabbix, self.send_cef_syslog,self.send_telegram, self.send_slack]


		print('[*] A.R.T.L.A.S Started!\n')

	def get_conf(self, config_file):
		config = ConfigParser()
		config.read(config_file)

		# Telegram
		self.conf['api'] = config.get('Telegram','api')
		self.conf['group_id'] = int(config.get('Telegram','group_id'))
		# One should use getboolean to fetch boolean values, otherwise they will always be True unless empty
		self.conf['telegram_enable'] = config.getboolean('Telegram','enable')

		# Slack
		self.conf['link_webhook'] = config.get('Slack', 'link_webhook')
		self.conf['slack_enable'] = config.getboolean('Slack', 'enable')

		# Zabbix
		self.conf['server_name'] = config.get('Zabbix','server_name')
		self.conf['agentd_config'] = config.get('Zabbix','agentd_config')
		self.conf['zabbix_advantage_keys'] = config.getboolean('Zabbix','enable_advantage_keys')
		self.conf['notifications'] = config.getboolean('Zabbix','notifications')
		self.conf['zabbix_enable'] = config.getboolean('Zabbix','enable')

		# Apache
		self.conf['apache_log'] = config.get('General', 'apache_log')
		self.conf['rules'] = config.get('General', 'rules')
		self.conf['whitelist'] = config.get('General', 'whitelist')
		self.conf['apache_mask'] = config.get('General', 'apache_mask')
		self.conf['vhost_enable'] = config.getboolean('General', 'vhost_enable')

		# CEF_Syslog
		self.conf['cef_syslog_enable'] = config.getboolean('CEF_Syslog','enable')
		self.conf['cef_syslog_server'] = config.get('CEF_Syslog','server_name')

		return self.conf

	def get_file_rules(self):
		r = requests.get('https://raw.githubusercontent.com/PHPIDS/PHPIDS/master/lib/IDS/default_filter.json')
		with open('etc/default_filter.json','w') as file_rules:
			file_rules.write(r.text)
			file_rules.close()

	def owasp(self, path):
		for filtro in self.rules['filters']['filter']:
			if filtro['id'] in self.white_rules:
				continue
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
					metrics = [ZabbixMetric(self.conf['server_name'], 'artlas_check{}'.format('_0{}'.format(impact) if impact in allowed_range else ''), "OK")]
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

	def send_slack(self, log):
		if self.conf['slack_enable']:
			msg = self.verbose_format(log)
			sleep(3)
			requests.post(self.conf['link_webhook'], headers={'Content-type': 'application/json'}, data='{{"text":"```{}```"}}'.format(msg))

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
	Description: {owasp_description}
	Status Code: {status}
	Rule ID: {rule_id}
	Impact: {owasp_impact}
	Category: {owasp_category}'''.format(rule_id=log['owasp']['id'], owasp_description=log['owasp']['description'], owasp_impact=log['owasp']['impact'], owasp_category=','.join(log['owasp']['tags']['tag']),cef_date=log['timestamp'],vhost=log['hostname'],remote_host=log['headers']['x-requester-id'],request_url=log['url'],request_header_user_agent=log['user-agent'],status=log['statusCode'])
			return msg

	def cef_format(self, log):

			msg = 'CEF:0|ARTLAS|ARTLAS|1.0|INTRUSION_ATTEMPT|Intrusion Attempt|{owasp_impact}|end={cef_date} cs1={vhost} cs1Label=Vhost src={remote_host}\=request={request_url} requestClientApplication="{request_header_user_agent__browser__family} {request_header_user_agent__os__family} {request_header_user_agent__browser__version_string}"\
 message={owasp_description} cs2={owasp_category} cs2Label=Category'.format(owasp_description=log['owasp']['description'], owasp_impact=log['owasp']['impact'], owasp_category=','.join(log['owasp']['tags']['tag']),cef_date=log['timestamp'],vhost=log['hostname'],remote_host=log['headers']['x-requester-id'],request_url=log['url'],request_header_user_agent=log['user-agent'],status=log['statusCode'])

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
				self.send_all(log)
		except:
			pass
		try:
			log=linha
			if "body" in log:
				if log['body'] == "Bad Request":
					url=log['body']['url']
				else:
					url=log['url']
				if "statusCode" not in log:
					log['statusCode'] = "Null"
				if "url" not in log and "url" not in log['body']:
					url = "Null"
				url=url.replace("[masked_session_id]","").replace("[masked_api_key]","")
				log['url'] = url
				log['owasp'] = self.owasp(log['url'])
				if log['owasp']:
					self.send_all(log)
		except Exception as e:
			print(e,"error")
			pass

	def run(self):
		try:
			process = subprocess.Popen(shlex.split("aws logs tail $GROUP_NAME --follow --profile $PROFILE --region us-east-1 --format short --since 5m"), stdout=subprocess.PIPE)
			while True:
				output = process.stdout.readline()
				if output == '' and process.poll() is not None:
					break
				if output:
					rec=output[20:].strip().decode("utf-8")
					if '{"service":' in rec:
						rec=json.loads(rec)
						rec['timestamp']=output[:20].strip()
						t = Thread(target=self.connections, args=(rec,))
						t.start()
		# Prevent processing overflow
		except Exception as e:
			print(e)
			exit()
		finally:
			sleep(0.01)


if __name__ == '__main__':
	artlas = ARTLAS('etc/artlas.conf')
	artlas.run()
