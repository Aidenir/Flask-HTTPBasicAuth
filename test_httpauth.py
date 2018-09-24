import unittest
import base64
import re
from flask import Flask, g
from flask_httpauth import HTTPBasicAuth, HTTPDigestAuth
from werkzeug.http import parse_dict_header



class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        basic_auth = HTTPBasicAuth()
        basic_auth_my_realm = HTTPBasicAuth()
        basic_auth_my_realm.realm = 'My Realm'
        basic_custom_auth = HTTPBasicAuth()
        basic_verify_auth = HTTPBasicAuth()

        @basic_auth.get_password
        def get_basic_password(username):
            if username == 'john':
                return 'hello'
            elif username == 'susan':
                return 'bye'
            else:
                return None

        @basic_auth_my_realm.get_password
        def get_basic_password_2(username):
            if username == 'john':
                return 'johnhello'
            elif username == 'susan':
                return 'susanbye'
            else:
                return None

        @basic_auth_my_realm.hash_password
        def basic_auth_my_realm_hash_password(username, password):
            return username + password

        @basic_auth_my_realm.error_handler
        def basic_auth_my_realm_error():
            return 'custom error'

        @basic_custom_auth.get_password
        def get_basic_custom_auth_get_password(username):
            if username == 'john':
                return md5('hello').hexdigest()
            elif username == 'susan':
                return md5('bye').hexdigest()
            else:
                return None

        @basic_custom_auth.hash_password
        def basic_custom_auth_hash_password(password):
            return md5(password).hexdigest()

        @basic_verify_auth.verify_password
        def basic_verify_auth_verify_password(username, password):
            g.anon = False
            if username == 'john':
                return password == 'hello'
            elif username == 'susan':
                return password == 'bye'
            elif username == '':
                g.anon = True
                return True
            return False

        @app.route('/')
        def index():
            return 'index'

        @app.route('/basic')
        @basic_auth.login_required
        def basic_auth_route():
            return 'basic_auth:' + basic_auth.username()

        @app.route('/basic-with-realm')
        @basic_auth_my_realm.login_required
        def basic_auth_my_realm_route():
            return 'basic_auth_my_realm:' + basic_auth_my_realm.username()

        @app.route('/basic-custom')
        @basic_custom_auth.login_required
        def basic_custom_auth_route():
            return 'basic_custom_auth:' + basic_custom_auth.username()

        @app.route('/basic-verify')
        @basic_verify_auth.login_required
        def basic_verify_auth_route():
            return 'basic_verify_auth:' + basic_verify_auth.username() + \
                ' anon:' + str(g.anon)

        self.app = app
        self.basic_auth = basic_auth
        self.basic_auth_my_realm = basic_auth_my_realm
        self.basic_custom_auth = basic_custom_auth
        self.basic_verify_auth = basic_verify_auth
        self.client = app.test_client()

    def test_no_auth(self):
        response = self.client.get('/')
        self.assertEqual(response.data.decode('utf-8'), 'index')

    def test_basic_auth_prompt(self):
        response = self.client.get('/basic')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')

    def test_basic_auth_ignore_options(self):
        response = self.client.options('/basic')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('WWW-Authenticate' not in response.headers)

    def test_basic_auth_prompt_with_custom_realm(self):
        response = self.client.get('/basic-with-realm')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="My Realm"')
        self.assertEqual(response.data.decode('utf-8'), 'custom error')

    def test_basic_auth_login_valid(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/basic', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data.decode('utf-8'), 'basic_auth:john')

    def test_basic_auth_login_valid_with_hash1(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/basic-custom', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data.decode('utf-8'),
                         'basic_custom_auth:john')

    def test_basic_auth_login_valid_with_hash2(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/basic-with-realm', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data.decode('utf-8'),
                         'basic_auth_my_realm:john')

    def test_basic_auth_login_invalid(self):
        creds = base64.b64encode(b'john:bye').decode('utf-8')
        response = self.client.get(
            '/basic-with-realm', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="My Realm"')

    def test_basic_custom_auth_login_valid(self):
        creds = base64.b64encode(b'john:hello').decode('utf-8')
        response = self.client.get(
            '/basic-custom', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'basic_custom_auth:john')

    def test_basic_custom_auth_login_invalid(self):
        creds = base64.b64encode(b'john:bye').decode('utf-8')
        response = self.client.get(
            '/basic-custom', headers={"Authorization": "Basic " + creds})
        self.assertEqual(response.status_code, 401)
        self.assertTrue("WWW-Authenticate" in response.headers)

    def test_verify_auth_login_valid(self):
        creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = self.client.get(
            '/basic-verify', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.data, b'basic_verify_auth:susan anon:False')

    def test_verify_auth_login_empty(self):
        creds = base64.b64encode(b'susan:bye').decode('utf-8')
        response = self.client.get('/basic-verify')
        self.assertEqual(response.data, b'basic_verify_auth: anon:True')

    def test_verify_auth_login_invalid(self):
        creds = base64.b64encode(b'john:bye').decode('utf-8')
        response = self.client.get(
            '/basic-verify', headers={'Authorization': 'Basic ' + creds})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)

def suite():
    return unittest.makeSuite(HTTPAuthTestCase)

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
