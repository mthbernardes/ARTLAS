<h1>ARTLAS Apache Real Time Logs Analyzer System</h1>

<p>
Real time  Apache log analyzer, based on top 10 OWASP vulnerabilities, identifies attempts of exploration in your web application, and notify you or your incident team on Telegram.
</p>

<h3>Installation</h3>
<pre>
<b>Clone project</b>
git clone https://github.com/mthbernardes/ARTLAS.git

<b>Install dependencies</b>
pip install -r dependencies.txt
</pre>

<h3>Configuration</h3>
<pre>Edit the file etc/artlas.conf
<b>TELEGRAM INTEGRATION</b>
<i>[Telegram]
api = Your Token API
group_id = Group/User ID that will receive the notifications
enable = True to send notificantions or False to not send.</i>

<b><font color="red">**ZABBIX INTEGRATION NOT WORKING YET**</font></b>
<i>[Zabbix]
username = Zabbix Username
password = Zabbix Password
server = http://127.0.0.1/ - Zabbix Server
enable = True to enable  or False to disable

<b>GENERAL CONFIGURATION</b>
[Files]
apache_log = Full path apache access.log
rules = default_filter.xml <b><i>Do not Change</i></b>
</pre>

<h3>Telegram Notification</h3>
<img src="https://raw.githubusercontent.com/mthbernardes/ARTLAS/master/img/notification.png" width="350"/>
