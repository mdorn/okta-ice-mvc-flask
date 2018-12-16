import base64
import json
import logging
import os
from functools import wraps

from flask import request, abort


def configure_logging():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    import httplib2;httplib2.debuglevel = 1  # noqa


def generate_secrets_json():
    auth_server = '{}/oauth2/{}'.format(
        os.environ.get('OKTA_ORG_URL'),
        os.environ.get('AUTH_SERVER_ID')
    )
    conf = {
      'web': {
        'client_id': '{}'.format(os.environ.get('CLIENT_ID')),
        'client_secret': '{}'.format(os.environ.get('CLIENT_SECRET')),
        'auth_uri': '{}/v1/authorize'.format(auth_server),
        'token_uri': '{}/v1/token'.format(auth_server),
        'issuer': '/{}'.format(auth_server),
        'userinfo_uri': '/{}/userinfo'.format(auth_server),
        'redirect_uris': [
          'http://localhost:5000',
          'http://localhost:5000/oidc/callback'
        ],
        'token_introspection_uri': '{}/v1/introspect'.format(auth_server)
      }
    }
    output = json.dumps(conf, indent=4)
    with open('client_secrets.json', 'w') as file_:
        file_.write(output)


def _validate_access_token(oidc, scopes, request):
    # validate the access token; behind the scenes, flask_oidc makes use of the
    #   using the /introspect API endpoint for this
    # NOTE: token validation should be cached for the life of the token
    #   (until expiration date/time); ideally flask_oidc would do this for you
    #   but it does not currently do so.  As it is, you'll make a roundtrip
    #   to the server every time this is called.
    # Also: best to cache the JWK public keys and do manual validation that way
    validate = oidc.validate_token(
        request.cookies.get('access_token', None),
        scopes_required=scopes
    )
    if validate is not True:
        logging.warning('INVALID TOKEN: {}'.format(validate))
        abort(403)


def authorize(oidc, scopes):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            _validate_access_token(oidc, scopes, request)
            retval = function(*args, **kwargs)
            return retval
        return wrapper
    return decorator


def format_json(input):
    # TODO: handle both dicts and JSON strings
    if type(input) is dict:
        formatted = json.dumps(input, indent=4, sort_keys=True)
    else:
        dicted = json.loads(input)
        formatted = json.dumps(dicted, indent=4, sort_keys=True)
    return formatted


def parse_jwt_payload(token, dictify=False):
    # parse and decode JTW paylod without validation
    payload = token.split('.')[1]
    b64 = payload.replace('-', '+').replace('_', '/')
    missing_padding = len(b64) % 4
    if missing_padding:
        b64 += b'=' * (4 - missing_padding)
    decoded = base64.b64decode(b64)
    if dictify:
        return json.loads(decoded)
    return decoded


def get_data():
    with open('./data.json', 'r') as file_:
        data = json.loads(file_.read())
    return data


def is_premium_user(request):
    token = parse_jwt_payload(request.cookies.get('access_token'), True)
    if 'Okta Ice Premium Customers' in token['groups']:
        return True
    return False
