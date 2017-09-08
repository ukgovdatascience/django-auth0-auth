from django.contrib.auth import authenticate
from django.core.urlresolvers import reverse
from django.test import Client, TestCase


class LoginTest(TestCase):
    def setUp(self):
        self.client = Client()

    def test_login_url(self):
        url = reverse('auth0_login')
        response = self.client.get(url)
        print response.url

    def test_logout_url(self):
        url = reverse('auth0_logout')
        response = self.client.get(url)
        print response.url
