import telepot,time

Work = True

def get_conf():
    from ConfigParser import ConfigParser
    config = ConfigParser()
    config.read('artlas.conf')
    api = config.get('Telegram','api')
    return api

def message(msg):
    global Work
    print 'Group ID:' , msg['chat']['id']
    print 'Group Name: ' + msg['chat']['title']
    print
    print 'Username ID:', msg['from']['id']
    Work = False

api = get_conf()
bot = telepot.Bot(api)
bot.message_loop(message)

while Work == True:
    time.sleep(1)
