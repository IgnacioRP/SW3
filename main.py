import httplib
import json
import logging
import os
import jinja2
import urllib
import webapp2
from webapp2_extras import sessions

import httplib2


def do_urlescape(value):
    """Escape for use in URLs."""
    return urllib.quote(value.encode('utf8'))


JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

JINJA_ENVIRONMENT.globals['do_urlescape'] = do_urlescape

# Claves
client_id = "364280739195-pg4r0km6r1guvuvp8d8ts7f0i2jnchoh.apps.googleusercontent.com"
client_secret_id = "lKkSc2V6pGN7E3bz2hUtAa8x"
redirect_uri = "http://sistemaswebgae.appspot.com/callback_uri"


class BaseHandler(webapp2.RequestHandler):
    def dispatch(self):
        self.session_store = sessions.get_store(request=self.request)
        try:
            webapp2.RequestHandler.dispatch(self)
        finally:
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        return self.session_store.get_session()


config = {'webapp2_extras.sessions': {'secret_key': 'my-super-secret-key'}}


class MainHandler(webapp2.RequestHandler):
    def get(self):
        # Cargar template
        template = JINJA_ENVIRONMENT.get_template("index.html")

        # Renderizar template
        self.response.out.write(template.render())


class LoginAndAuthorize(BaseHandler):
    def get(self):
        servidor = 'accounts.google.com'
        conn = httplib.HTTPSConnection(servidor)
        conn.connect()
        metodo = 'GET'
        params = {'client_id': client_id,
                'redirect_uri': redirect_uri,
                'response_type': 'code',
                'scope': 'https://www.googleapis.com/auth/calendar',
                'approval_prompt': 'auto',
                'access_type': 'offline'}
        params_coded = urllib.urlencode(params)
        uri = '/o/oauth2/v2/auth' + '?' + params_coded
        self.redirect('https://' + servidor + uri)

class OAuthHandler(BaseHandler):
    def get(self):
        servidor = 'accounts.google.com'
        metodo = 'POST'
        uri = '/o/oauth2/token'
        auth_code = self.request.get('code')
        params = {'code': auth_code,
                  'client_id': client_id,
                  'client_secret': client_secret_id,
                  'redirect_uri': redirect_uri,
                  'grant_type': 'authorization_code'}
        params_encoded = urllib.urlencode(params)
        cabeceras = {'Host': servidor,
                     'User-Agent': 'Python bezeroa',
                     'Content-Type': 'application/x-www-form-urlencoded',
                     'Content-Length': str(len(params_encoded))}
        http = httplib2.Http()
        respuesta, cuerpo = http.request('https://' + servidor + uri, method=metodo, headers=cabeceras,
                                         body=params_encoded)

        json_cuerpo = json.loads(cuerpo)

        access_token = json_cuerpo['access_token']
        self.session['access_token'] = access_token
        self.redirect('/CalendarList')


class CalendarList(BaseHandler):
    def get(self):
        if self.session.get('access_token') is not None:
            access_token = self.session.get('access_token')
            servidor = 'www.googleapis.com'
            metodo = 'GET'
            uri = '/calendar/v3/users/me/calendarList'
            cabeceras = {'Host': servidor,
                         'Authorization': 'Bearer ' + access_token}
            http = httplib2.Http()
            respuesta, cuerpo = http.request('https://' + servidor + uri, method=metodo, headers=cabeceras)

            json_cuerpo = json.loads(cuerpo)

            # Cargar template
            template = JINJA_ENVIRONMENT.get_template("calendar_list.html")
            data = json_cuerpo

            # Renderizar template
            self.response.out.write(template.render(data))
        else:
            self.redirect('/')


class Calendar(BaseHandler):
    def get(self):
        if self.session.get('access_token') is not None:
            calendar_id = self.request.get('id')
            logging.debug(calendar_id)

            access_token = self.session.get('access_token')

            servidor = 'www.googleapis.com'
            metodo = 'GET'
            uri = '/calendar/v3/calendars/' + calendar_id + '/events'
            cabeceras = {'Host': servidor,
                         'Authorization': 'Bearer ' + access_token}
            http = httplib2.Http()
            uri = urllib.quote(uri)
            respuesta, cuerpo = http.request('https://' + servidor + uri, method=metodo, headers=cabeceras)
            logging.debug('https://' + servidor + uri)
            logging.debug(respuesta)
            logging.debug(cuerpo)
            json_cuerpo = json.loads(cuerpo)
            items = json_cuerpo['items']

            maps_api_key = 'AIzaSyCp4euew8vLAzkrFXt1UBBTTjMxxiGNCZI'

            for each in items:
                if 'location' in each:
                    location = each['location']
                    location = urllib.quote(location.encode('utf8'))
                    servidor = 'maps.googleapis.com/maps/api/geocode/json?address=' + location + '&key=' + maps_api_key
                    http = httplib2.Http()
                    respuesta, cuerpo = http.request('https://' + servidor)
                    json_cuerpo = json.loads(cuerpo)
                    if json_cuerpo['results'] != []:
                        each['coordinates'] = json_cuerpo['results'][0]['geometry']['location']

            # Cargar template
            template = JINJA_ENVIRONMENT.get_template("calendar.html")
            data = {'events': items}

            # Renderizar template
            self.response.out.write(template.render(data))
        else:
            self.redirect('/')


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/LoginAndAuthorize', LoginAndAuthorize),
    ('/callback_uri', OAuthHandler),
    ('/CalendarList', CalendarList),
    ('/Calendar', Calendar)], config=config, debug=True)
