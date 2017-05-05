import datetime
import pytz
import django
import base64
import hashlib
import json
from pprint import pprint
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.models import User, Group
from django.db import transaction
from .models import *
import unittest
from django.test import TestCase
from django.test import Client


def atomicly(func):
    """
    becasue django's unittest is run inside a transaction itself
    intentionaly causeing database errors with out rolling them back is a bad idea
    so if an error is expected we protect the func with this

    we explicitly create a new atomic block so the error will get rolled back
    """
    def call_atomicly(*args, **kwargs):
        with transaction.atomic():
            func(*args, **kwargs)

    return call_atomicly

class APIAuthTest(TestCase):
    """
    @invariants
        api must return valid json
    @pre-conditions
        reject un authenticated requests
            all of no token, bad token, and expired token
            should be rejected
    @post-conditions
        auth endpont gives auth tokens
        expire endpoint makes tokens invalid
        other endpoints reject
    """


    def valid_error_respone(self, res, code):
        self.assertEqual(res.status_code, code,
            msg="got responce code {} , expected {}".format(res.status_code, code))
        #valid JSON
        try:
            body = json.loads(res.content)
        except json.JSONDecodeError:
            self.fail("Json decode failed")
        res.body = body
        # should be a json object
        self.assertTrue(type(body) is dict, msg=None)
        # it has err and result keys
        self.assertTrue('err' in body, msg=None)
        self.assertTrue('result' in body, msg=None)
        # in this case we should have an error
        self.assertTrue(bool(body['err']), msg=None)
        #but no result
        self.assertFalse(bool(body['result']), msg=None)
        # should have msg, code, source keys
        self.assertTrue('msg' in body['err'], msg=None)
        self.assertTrue('code' in body['err'], msg=None)
        self.assertTrue('source' in body['err'], msg=None)
        # code matches status code
        self.assertEqual(body['err']['code'], res.status_code, msg=None)

    def valid_success_respone(self, res, keys=None):
        self.assertEqual(res.status_code, 200,
            msg="got responce code {} , expected {}".format(res.status_code, 200))
        #valid JSON
        try:
            body = json.loads(res.content)
        except json.JSONDecodeError:
            self.fail("Json decode failed")
        res.body = body
        # should be a json object
        self.assertTrue(type(body) is dict, msg=None)
        # it has err and result keys
        self.assertTrue('err' in body, msg=None)
        self.assertTrue('result' in body, msg=None)
        # in this case we should have a result
        self.assertTrue(bool(body['result']), msg=None)
        #but no err
        self.assertFalse(bool(body['err']), msg=None)

        result = body['result']

        if keys and type(keys) in (list, tuple):
            # does it have all the keys ew expect?
            for key in keys:
                self.assertTrue(key in result,
                    msg="no key {} in {}".format(key, result))

    def setUp(self):
        self.user = User.objects.create_user("apitest", email="test@test.com", password="APITest")
        self.token = AuthToken(user=self.user)
        self.token_invalid = AuthToken(user=self.user)
        self.token_expired = AuthToken(user=self.user)
        now = timezone.now()
        self.token.set_issue_time(time=now - datetime.timedelta(minutes=1))
        self.token.generate_token()
        self.token_invalid.set_issue_time(time=now - datetime.timedelta(minutes=2))
        self.token_invalid.generate_token()
        self.token_invalid.valid = False
        self.token_expired.set_issue_time(time=now - datetime.timedelta(hours=5))
        self.token_expired.generate_token()
        self.token.save()
        self.token_expired.save()
        self.token_invalid.save()

    def test_auth_bad_calls(self):

        # only post
        res = self.client.get('/api/auth/')
        self.valid_error_respone(res, 405)

        # need a user and pass
        res = self.client.post('/api/auth/')
        self.valid_error_respone(res, 400)
        res = self.client.post('/api/auth/',
            data={
                "user": "apitest"
            })
        self.valid_error_respone(res, 400)


    def test_good_auth(self):
        # a good login shoudl return the token and it's expiery
        res = self.client.post('/api/auth/',
            data={
                "user": "apitest",
                "pass": "APITest"
            })
        self.valid_success_respone(res, keys=('token', 'expires'))

    def test_bad_auth(self):

        #submit bad user pass combo
        res = self.client.post('/api/auth/',
            data={
                "user": "baduser",
                "pass": "testpass"
            })
        self.valid_error_respone(res, 403)
        res = self.client.post('/api/auth/',
            data={
                "user": "apitest",
                "pass": "apitest"
            })
        self.valid_error_respone(res, 403)

    def test_good_token_get_user(self):
        # this should work no problem
        res = self.client.get('/api/getuser/{}/'.format(self.user.id),
            HTTP_AUTHORIZATION='Token {}'.format(self.token.token))
        self.valid_success_respone(res, keys=('user'))

    def test_bad_token_get_user(self):
        # expired token
        res = self.client.get('/api/getuser/{}/'.format(self.user.id),
            HTTP_AUTHORIZATION='Token {}'.format(self.token_expired.token))
        self.valid_error_respone(res, 401)
        # invalid token
        res = self.client.get('/api/getuser/{}/'.format(self.user.id),
            HTTP_AUTHORIZATION='Token {}'.format(self.token_invalid.token))
        self.valid_error_respone(res, 401)

    def test_expire_endpoint(self):
        # expireing a bad token should not work
        # I mean we shouldn;t even but authed!
        res = self.client.get('/api/expire/'.format(self.user.id),
            HTTP_AUTHORIZATION='Token {}'.format(self.token_expired.token))
        self.valid_error_respone(res, 401)
        res = self.client.get('/api/expire/'.format(self.user.id),
            HTTP_AUTHORIZATION='Token {}'.format(self.token_invalid.token))
        self.valid_error_respone(res, 401)

        # but a good token should get marked invalid
        res = self.client.get('/api/expire/'.format(self.user.id),
            HTTP_AUTHORIZATION='Token {}'.format(self.token.token))
        self.valid_success_respone(res, keys=('success'))
        # adn then be unuseable
        res = self.client.get('/api/expire/'.format(self.user.id),
            HTTP_AUTHORIZATION='Token {}'.format(self.token.token))
        self.valid_error_respone(res, 401)


# Create your tests here.
class AuthTokenTest(TestCase):
    """
    @invariants
        tokens with same user and issued time are the same digest
        tokens but be valid base64 encoded data
        tokens data must be a 256 bit sha hash
    @pre-conditions
        tokens need a user before they can be Generated
        tokens must be generated and have an expiery before they can save
    @post-conditions
        only one token with a given same digest can exist in the database
            (save should fail)
        expires time stamp should be ahead of issued timestamp by the set number of hours
    """

    def setUp(self):
        self.user = User()
        self.user.username = "testuser"
        self.user.set_password("testpass")
        self.user.save()

        self.token = AuthToken()
        self.token.user = self.user
        self.token.generate_token()
        self.token.save()

    def test_token_gen(self):
        t = AuthToken()
        # cant gen token, no user
        self.assertRaises(django.core.exceptions.ValidationError, atomicly(t.save))
        # cant save it's not generated
        self.assertRaises(django.core.exceptions.ValidationError, atomicly(t.save))

        # add user

        t.user = self.user
        # still not generated
        self.assertRaises(django.core.exceptions.ValidationError, atomicly(t.save))

        # three years and some change after unix epoch...
        d = datetime.datetime(1973, 1, 1, 12, 30, 42, tzinfo=pytz.utc)
        de = d + datetime.timedelta(hours=settings.TOKEN_AUTH_HOURS)

        # sets issued time and expirey
        t.set_issue_time(d)
        # we got the date right?
        self.assertEqual(t.issued, d,  msg="{} != {}".format(t.issued, d))
        # and we set the expiery right?
        self.assertEqual(t.expires, de,  msg="{} != {}".format(t.issued, de))

        # still can't save not generated
        self.assertRaises(django.core.exceptions.ValidationError, atomicly(t.save))
        # gen token
        t.generate_token()
        try:
            atomicly(t.save)() # oh good we can save now
        except:
            self.assertTrue(False, msg="the token failed to save")

    def test_token_issue_now_on_gen(self):

        t2 = AuthToken()
        t2.user = self.user
        #but wait, if generating before setting date it should get auto set to now!
        now = timezone.now()
        fudge = now + datetime.timedelta(seconds=2) # wow thus number needs to be big...
        t2.generate_token()
        # the actualt set opperation happend AFTER we stored no so test a range with some fudge
        self.assertTrue(t2.issued >= now and t2.issued <= fudge,
            msg="{} < {} < {} != True".format(now, t2.issued, fudge))
        try:
            atomicly(t2.save)() # oh good we can save now
        except:
            self.assertTrue(False, msg="the token failed to save")


    def test_token_dup(self):

        # if we create a token with the same user and time stamp as another token...
        t3 = AuthToken()
        t3.user = self.user
        t3.set_issue_time(self.token.issued)
        # we should get the same digest
        t3.generate_token()
        self.assertEqual(t3.token, self.token.token,
            msg="{} != {}".format(t3.token, self.token.token))
        # but there is already a token with that digest so it should not save
        self.assertRaises(django.core.exceptions.ValidationError, atomicly(t3.save))

    def test_token_data(self):

        # token set up
        t4 = AuthToken()
        t4.user = self.user
        t4.set_issue_time()

        # tokens donmt save with just ant data as the tokens
        # token data must be base64
        t4.token = "abc"
        self.assertRaises(django.core.exceptions.ValidationError, t4.clean_fields)

        # and not just any base64 data will do. we need a sha256 hash!
        # that means the data needs to be 32 bytes long
        t4.token =  base64.urlsafe_b64encode(bytes(1) * 8).decode()
        self.assertRaises(django.core.exceptions.ValidationError, t4.clean_fields)
        t4.token =  base64.urlsafe_b64encode(bytes(1) * 64).decode()
        self.assertRaises(django.core.exceptions.ValidationError, t4.clean_fields)
        t4.token =  base64.urlsafe_b64encode(bytes(1) * 32).decode()
        try:
            t4.clean_fields()
        except django.core.exceptions.ValidationError:
            self.fail('32 bytes encoded base64 should be valid')

        #test a sha256 proper
        t4.token = base64.urlsafe_b64encode(hashlib.sha256("test".encode()).digest()).decode()
        try:
            t4.clean_fields()
        except django.core.exceptions.ValidationError:
            self.fail('32 bytes encoded base64 should be valid')
