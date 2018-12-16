'''
A simple Flask app that showcases how to easily register and login users using
OpenID Connect.
'''


from os import environ
import time

from flask import (
    Flask,
    g,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_oidc import OpenIDConnect
from okta import UsersClient
from dotenv import load_dotenv

from util import (
    generate_secrets_json,
    authorize,
    configure_logging,
    format_json,
    parse_jwt_payload,
    get_data,
    is_premium_user
)

load_dotenv()
generate_secrets_json()
configure_logging()

DEFAULT_SCOPES = ['openid', 'email', 'profile', 'promos:read']
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['OIDC_CLIENT_SECRETS'] = 'client_secrets.json'
app.config['OIDC_COOKIE_SECURE'] = False
app.config['OIDC_CALLBACK_ROUTE'] = '/oidc/callback'
app.config['OIDC_SCOPES'] = DEFAULT_SCOPES
app.config['SECRET_KEY'] = environ.get('SECRET_KEY')
app.config['OIDC_ID_TOKEN_COOKIE_NAME'] = 'id_token'

oidc = OpenIDConnect(app)
okta_client = UsersClient(
    environ.get('OKTA_ORG_URL'), environ.get('OKTA_API_TOKEN'))


@app.before_request
def before_request():
    '''
    Load a proper user object using the user ID from the ID token. This way,
    the `g.user` object can be used at any point.
    '''
    if oidc.user_loggedin:
        id_token = oidc.get_cookie_id_token()
        g.user = {
            'id': id_token.get('sub', None),
            'name': id_token.get('name', None),
            'email': id_token.get('email', None),
        }
        # NOTE: you can get basic ID info from the id_token this way.
        # If you need more info like First Name, job title, etc. from
        # the profile, you can query the API for it like so:
        # g.user = okta_client.get_user(oidc.user_getfield('sub'))
    else:
        g.user = None


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard')
@oidc.require_login
def dashboard():
    # NOTE: ideally flask_oidc would provide an easy way to
    #   get parsed access_token like it does for the id_token;
    #   since it doesn't we handle decode with our own util function
    # access_token = oidc.get_access_token()
    access_token = request.cookies.get('access_token', None)
    tokens = {
        'id_token': format_json(oidc.get_cookie_id_token()),
        'access_token': format_json(parse_jwt_payload(access_token)),
    }
    return render_template('dashboard.html', **tokens)


@app.route('/promos')
@authorize(oidc, DEFAULT_SCOPES)
def promos():
    data = get_data()
    if is_premium_user(request):
        promos = data['PUBLIC'] + data['PREMIUM']
    else:
        promos = data['PUBLIC']
    return render_template('promos.html', promos=promos)


@oidc.accept_token
@app.route('/login')
@oidc.require_login
def login():
    access_token = oidc.get_access_token()
    response = make_response(redirect(url_for('.dashboard')))
    # NOTE: flask_oidc already sets the id_token cookie for us,
    #   we'll set the access_token here
    parsed = parse_jwt_payload(access_token, True)
    token_expire = parsed['exp'] - time.time()
    response.set_cookie('access_token', access_token, max_age=token_expire)
    return response


@app.route('/logout')
def logout():
    # NOTE: to end the Okta session as well, you can DELETE it using the
    #   sessions API
    oidc.logout()
    response = make_response(redirect(url_for('.index')))
    response.set_cookie('access_token', '', max_age=0)
    return response


@app.errorhandler(403)
def page_not_found(e):
    return render_template('403.html'), 403
