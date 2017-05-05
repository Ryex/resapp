import datetime
from pprint import pprint
import pytz
import django
from django.test import TestCase
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.models import User, Group
from django.db import transaction
from .models import *

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

# Create your tests here.
class AuthTokenTest(TestCase):
    """
    @invariants
        tokens with same user and issued time are the same digest
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
        fudge = now + datetime.timedelta(microseconds=5000) # wow thus number needs to be big...
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
