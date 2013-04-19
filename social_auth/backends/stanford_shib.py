"""
Shibboleth support for logging in with the Stanford IdP.  Note that this does
not do any SAML traffic at all--instead it relies on Apache and modshib to 
pass authenticated credentials via environment variables.  So this essentially
just reads environment to get user details.
"""
from urllib import urlencode

from django.contrib.auth import authenticate
from django.utils import simplejson
from django.http import HttpResponse
from django.core.urlresolvers import reverse

from social_auth.backends import SocialAuthBackend, BaseAuth
from social_auth.utils import log, dsa_urlopen
from social_auth.exceptions import AuthFailed, AuthMissingParameter


class StanfordShibBackend(SocialAuthBackend):
    """Stanford Shibboleth authentication backend"""
    name = 'stanford_shib'

    def get_user_id(self, details, response):
        """Use email as ID"""
        return details['email']

    def get_user_details(self, response):
        """Return user details, BrowserID only provides Email."""
        # {'status': 'okay',
        #  'audience': 'localhost:8000',
        #  'expires': 1328983575529,
        #  'email': 'name@server.com',
        #  'issuer': 'login.persona.org'}
        email = response['email']
        return {'username': email.split('@', 1)[0],
                'email': email,
                'fullname': '',
                'first_name': '',
                'last_name': ''}

    def extra_data(self, user, uid, response, details):
        """Return users extra data"""
        return {
            'audience': response['audience'],
            'issuer': response['issuer']
        }


# Auth classes
class StanfordShibAuth(BaseAuth):
    """Stanford Shibboleth authentication"""
    AUTH_BACKEND = StanfordShibBackend
    uses_redirect = True
    
    def auth_url(self):
        """
            Must return redirect URL to auth provider.
            We needs to set up apache so that the url mapping to the
            "socialauth_complete" view uses modshib to fill out the
            shibboleth auth parameters.
        """
        return reverse('socialauth_complete', args=[self.AUTH_BACKEND.name])

    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance.
           We rely on the web server layer (Apache) to have already gone through
           the authentication at the URL for the view.  So we only need to
           read the parameters provided in request.META
        """"
        request = self.request
        meta = request.META
        if meta.get('eppn', ''):
            #If we get here, shib says user has authenticated properly.
            shib = {
                'username'   : meta.get('eppn', ''),
                'last_name'  : meta.get('sn', '').split(';')[0].capitalize(),
                'first_name' : meta.get('givenName', '') \
                                   .split(';')[0].capitalize(),
                'idp'        : meta.get('Shib-Identity-Provider', ''),
                'fullname'   : meta.get('displayName') \
                                   if meta.get('displayName','') else \
                               "%s %s" % \
                                      (shib['first_name'], shib['last_name']),
                'mail'       : meta.get('mail') if meta.get('mail', '') else \
                               meta.get('eppn')
            }
            return HttpResponse(unicode(shib))
        else:
            raise AuthFailed(self)
        

#        
#        if not 'assertion' in self.data:
#            raise AuthMissingParameter(self, 'assertion')
#
#        data = urlencode({
#            'assertion': self.data['assertion'],
#            'audience': self.request.get_host()
#        })
#
#        try:
#            response = simplejson.load(dsa_urlopen(BROWSER_ID_SERVER,
#                                                   data=data))
#        except ValueError:
#            log('error', 'Could not load user data from BrowserID.',
#                exc_info=True)
#        else:
#            if response.get('status') == 'failure':
#                log('debug', 'Authentication failed.')
#                raise AuthFailed(self)
#
#            kwargs.update({
#                'auth': self,
#                'response': response,
#                self.AUTH_BACKEND.name: True
#            })
#            return authenticate(*args, **kwargs)


# Backend definition
BACKENDS = {
    'stanford_shib': StanfordShibAuth
}
