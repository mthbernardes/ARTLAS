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
<b>Telegram</b>

<i>[Telegram]
api = Your Token API
group_id = Group/User ID that will receive the notifications
enable = True to send notificantions or False to not send.</i></pre>


<h3>Telegram Notification</h3>
<img src="https://raw.githubusercontent.com/mthbernardes/ARTLAS/master/img/notification.png" width="350"/>
