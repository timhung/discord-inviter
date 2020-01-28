from flask import Flask, request, render_template, make_response, redirect, url_for
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, RadioField
from wtforms.validators import DataRequired, Regexp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
import configparser
import requests
import sqlite3
import json
import uuid
import string
import random
import datetime

app = Flask(__name__)

# Get configuration options
config = configparser.ConfigParser()
config.read('config.ini')

app.secret_key = config['KEYS']['SECRET_KEY']

app.config['RECAPTCHA_PUBLIC_KEY'] = config['RECAPTCHA']['SITE_KEY']
app.config['RECAPTCHA_PRIVATE_KEY'] = config['RECAPTCHA']['PRIVATE_KEY']
app.config['RECAPTCHA_DATA_ATTRS'] = {'bind': 'captcha-submit', 'callback': 'onSubmitCallback', 'size': 'invisible'}

webhook_url = config['DISCORD']['WEBHOOK_URL']
discord_token = config['DISCORD']['BOT_TOKEN']
channel_id = config['DISCORD']['CHANNEL_ID']

# Create database if necessary
try:
    connection = sqlite3.connect('file:invites.db?mode=rw', uri=True)
except sqlite3.OperationalError:
    with open('db-schema.sql') as schema:
        connection = sqlite3.connect('invites.db')
        cur = connection.cursor()
        cur.executescript(schema.read())
        connection.commit()


# Create form for requesting Discord invite
class InviteForm(FlaskForm):
    username = StringField('name', validators=[DataRequired(), Regexp('^[A-Za-z0-9_-]{3,20}$')])
    role = RadioField('role', choices=[('tutor', '<i class="fas fa-chalkboard-teacher fa-3x"></i>'),
                                       ('student', '<i class="fas fa-graduation-cap fa-3x"></i>'),
                                       ('other', '<i class="fas fa-comments fa-3x"></i>')],
                      validators=[DataRequired()])
    captcha = RecaptchaField()


# Rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address
)

# API endpoints
discord_api = 'https://discordapp.com/api'
location_api = 'https://tools.keycdn.com/geo.json?host='

# Set Discord invite expiration
try:
    invite_expire_minutes = int(config['DISCORD']['INVITE_EXPIRE_MINUTES'])
    invite_timeout = invite_expire_minutes * 60
except KeyError:
    invite_timeout = 300


def get_invite(username, purpose):
    invite_header = {'Authorization': 'Bot {}'.format(discord_token),
                     'User-Agent': 'Discord custom invite generator',
                     'Content-Type': 'application/json',
                     'X-Audit-Log-Reason': 'Invite created for ' + username + ' (' + purpose + ')'}
    invite_payload = json.dumps({'max_age': invite_timeout, 'max_uses': 1, 'unique': True})
    invite = requests.post(discord_api + '/channels/' + channel_id + '/invites',
                           headers=invite_header, data=invite_payload)
    return json.loads(invite.content)['code']


def get_fake_invite():
    return ''.join(random.choice(string.ascii_letters) for x in range(5))


def get_geolocation(ip):
    response = requests.get(location_api + ip).json()
    if response['status'] == 'success':
        city = response['data']['geo']['city']
        country = response['data']['geo']['country_name']
        isp = response['data']['geo']['isp']
        location = ' (' + city + ', ' + country + '. ISP: ' + isp + ')'
    else:
        location = 'Unable to resolve IP'
    return location


@app.errorhandler(Exception)
def error_handler(e):
    if isinstance(e, HTTPException):
        code = e.code
    else:
        code = 500
    if code == 404:
        description = 'Page not found.'
    elif code == 429:
        description = 'You\'ve requested too many invites today. Please try again tomorrow or contact a moderator.'
    else:
        description = 'Something went wrong. Please contact a moderator for details.'
    return make_response(render_template('error.html', error_code=code, description=description), code)


@app.route('/', methods=['GET', 'POST'])
@app.route('/<reference>', methods=['GET', 'POST'])
@limiter.limit("5 per day", exempt_when=lambda: request.method == 'GET')
def index(reference='direct'):
    form = InviteForm()
    if form.validate_on_submit():
        username = form.username.data
        purpose = form.role.data
        ip = request.remote_addr
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
        if 'reference' in request.cookies:
            reference = request.cookies.get('reference')
        else:
            return redirect(url_for('index'))
        if 'uuid' in request.cookies:
            uuid_ = request.cookies.get('uuid')
        else:
            return redirect(url_for('index'))

        # Check for bans based on IP and UUID
        connection = sqlite3.connect('invites.db')
        cur = connection.cursor()
        cur.execute('SELECT COUNT(*) FROM Ban WHERE IP = ?', (ip,))
        result = cur.fetchone()[0]
        cur.execute('SELECT COUNT(*) FROM Ban WHERE UUID = ?', (uuid_,))
        result += cur.fetchone()[0]
        if result != 0:
            banned = True
            connection = sqlite3.connect('invites.db')
            cur = connection.cursor()
            cur.execute('INSERT INTO Hit (Timestamp, IP, UUID) VALUES (?, ?, ?)', (now, ip, uuid_))
            cur.execute('INSERT OR IGNORE INTO Ban (Timestamp, IP, UUID, Reason) VALUES (?, ?, ?)',
                        (now, ip, uuid_, 'Ban evasion'))
            connection.commit()
        else:
            banned = False

        # Save requestor data to database
        connection = sqlite3.connect('invites.db')
        cur = connection.cursor()
        cur.execute('INSERT INTO Invite (Timestamp, Username, Purpose, IP, UA, Language, Reference, UUID)'
                    'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    (now, username, purpose, ip, request.headers.get('User-Agent'), request.headers.get('Accept-Language'),
                     reference, uuid_))
        connection.commit()

        # Announce invite request to Discord channel
        location = get_geolocation(ip)
        payload = {'content': '[' + username + '](https://reddit.com/user/' + username + ')' +
                   ' has requested a Discord invite from ' + ip + location +
                   ' and selected role as ' + purpose + '.\nReference: ' + reference + '\nUUID: ' + uuid_ +
                   '\nBanned: ' + str(banned)}
        requests.post(webhook_url, data=payload)

        # Get invite and return result
        if banned:
            invite_code = get_fake_invite()
        else:
            invite_code = get_invite(username, purpose)
        return render_template('result.html', discord_invite=invite_code, invite_timeout=invite_timeout)

    response = make_response(render_template('request.html', form=form))
    if 'reference' not in request.cookies:
        response.set_cookie('reference', reference)
    if 'uuid' not in request.cookies:
        response.set_cookie('uuid', uuid.uuid4().hex, max_age=15552000)  # 180 days
    return response


@app.route('/privacy/', methods=['GET'])
def privacy():
    return render_template('privacy.html')


@app.route('/help/', methods=['GET'])
def get_help():
    return render_template('help.html')


if __name__ == '__main__':
    app.run()
