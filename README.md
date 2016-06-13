<h1>ARTLAS Apache Real Time Logs Analyzer System</h1>

<p>
Real time  Apache log analyzer, based on top 10 OWASP vulnerabilities, identifies attempts of exploration in your web application, and notify you or your incident team on Telegram, Zabbix and Syslog/SIEM.
</p>
<p>
ARTLAS uses the regular expression from the PHP-IDS project, to identify the attempts of exploration, download link to the latest version of the file
<a href="https://dev.itratos.de/projects/php-ids/repository/raw/trunk/lib/IDS/default_filter.json">Download File</a>
</p>

<h3>Supported Output</h3>
<pre>
<b>Zabbix</b>
<b>SySlog</b>
<b>SIEM</b>
<b>Telegram</b>
</pre>

<h3>Supported web servers</h3>
<pre>
<b>Apache</b>
<b>Apache vHost</b>
<b>Nginx</b>
<b>Nginx vHost</b>
</pre>

<h3>Installation</h3>
<pre>
<b>Clone project</b>
git clone https://github.com/mthbernardes/ARTLAS.git

<b>Install dependencies</b>
pip install -r dependencies.txt
python version 2.7.11(lastet)

<b>Install screen</b>
sudo apt-get install screen #Debian Like
sbopkg -i screen    # Slackware 14.*
yum install screen # CentOS/RHEL   
dnf install screeen  # Fedora

<a href="http://www.nanoshots.com.br/2016/05/screen-dicas-de-administracao-de-varios.html"><i>screen tutorial [pt_Br]</i></a>
</pre>

<h3>Configuration</h3>
<pre>All your configurations will be made in <b>etc/artlas.conf</b> file.

<b>TELEGRAM INTEGRATION</b>
<i>[Telegram]
api = Your Token API
group_id = Group/User ID that will receive the notifications
enable = True to send notificantions or False to not send.</i>

<b>ZABBIX CONFIGURATION</b>
<i>[Zabbix]</i>
server_name = hostname of the server in zabbix
agentd_config = Zabbix agent configuration file
enable_advantage_keys = True or False to use advanced triggers
notifications = true to enable  or false to disable triggers notifications
enable = true to enable  or false to disable

<b>SYSLOG/SIEM CONFIGURATION</b>
[CEF_Syslog]
server_name = IP or Hostname SySlog/SIEM server
enable = True or False to enable

<b>GENERAL CONFIGURATION</b>
[General]
apache_log = Full path apache access.log
apache_mask = Mask to identify the fields in the apache access log
vhost_enable = True to enable  or False to disable vhosts
rules = etc/default_filter.json It's the file that contains the OWASP filter <b><i>[Do not Change]</i></b>

</pre>

<h3>How to start</h3>
<pre>
screen -S artlas
python artlas.py
CTRL+A+D
</pre>

<h3>Team</h3>
<pre>
<b>Matheus Bernardes a.k.a. G4mbler</b>
<b>Henrique Gonçalves a.k.a. <a href="https://github.com/kamushadenes">Kamus Hadenes</a></b>
<b>André Déo</b>
</pre>
