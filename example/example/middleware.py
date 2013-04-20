from django.core.urlresolvers import reverse

from social_auth.exceptions import AuthAlreadyAssociated
from social_auth.middleware import SocialAuthExceptionMiddleware


class ExampleSocialAuthExceptionMiddleware(SocialAuthExceptionMiddleware):
    def raise_exception(self, request, exception):
        return False

    def get_message(self, request, exception):
        if isinstance(exception, AuthAlreadyAssociated):
            return 'Somebody is already using that account!'
        return super(ExampleSocialAuthExceptionMiddleware, self)\
                        .get_message(request, exception)

    def get_redirect_uri(self, request, exception):
        if request.user.is_authenticated():
            return reverse('done')
        else:
            return reverse('error')

#    def process_request(self, request):
#        shib = {
#            'eppn'       : 'jbau1@stanford.edu',
#            'sn'         : 'Bau',
#            'givenName'  : 'Jason',
#            'Shib-Identity-Provider'        : 'idp.stanford.edu',
#            'displayName'   : 'Jason Hsi-Chieh Bau',
#            'email'       : 'jbau@stanford.edu',
#        }
#        request.META.update(shib)
