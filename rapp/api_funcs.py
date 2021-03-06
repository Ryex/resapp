import base64
import hashlib
import datetime
import traceback
import json
from django.http import JsonResponse
from django.utils import timezone
import django.contrib.auth
from django.core.exceptions import ObjectDoesNotExist
from .models import *
from django.contrib.auth.models import User, Group


def private_or_callable(k, v):
    return k.startswith("_") or callable(v)


def get_properties(obj):
    props = {k: v for k, v in vars(obj).items() if not private_or_callable(k, v)}
    return props


def is_normal_type(obj):
    return type(obj) in (int, str, bool, list, dict, tuple)


def extend_depth(props):
    ext = {k: v if is_normal_type(v) else get_properties(v) for k, v in props.items()}
    return ext


def trunate_to_ids(props):
    trunc = {k: v if is_normal_type(v) or not hasattr(v, "id") else getattr(v, "id") for k, v in props.items()}
    return trunc


def protect_api(func):

    def protect(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            return render_json(None, {
                "msg": str(e),
                "code": 500,
                "source": "api",
                "trace": traceback.format_exc()
            })
    return protect


def api_url(urlpat):
    """a decorator function to tag function with their param regexp"""
    def decorate(func):
        protected = protect_api(func)
        protected.__urlpattern__ = urlpat
        return protected
    return decorate


def render_json(result, err):
    """renders out a consistant json responce"""
    status = 200

    if err is None:
        if result is None:
            err = {
                "msg": "Not Implimented",
                "code": 501,
                "source": "API"
            }
            status = 501
    else:
        status = err["code"]

    res = {
        "err": err,
        "result": result
    }

    return JsonResponse(res, status=status)


def authorize(func):
    '''
    if the header looks like
    "Authorization: Token 4SMPkrseLzXWYxoaDrTrQOzIwmb3IJCrSc40RvKqkpM="
    take the token and authorise a user
    set req.user to the user object
    '''
    def auth_wrapper(req, *args, **kwargs):
        auth_header = req.META.get('HTTP_AUTHORIZATION')

        if not auth_header:
            return render_json(
                None,
                {
                    "msg": "Not Authorized",
                    "code": 401,
                    "source": "Auth"
                }
            )

        header_parts = auth_header.split(' ')
        authflag = False
        if len(header_parts) == 2 and header_parts[0].upper() == 'TOKEN':
            token = header_parts[1]
            user = None
            try:
                token = AuthToken.objects.get(token=token)
                if token.valid and timezone.now() < token.expires:
                    user = token.user
            except ObjectDoesNotExist:
                pass
            if user:
                req.user = user
                req.token = token
                authflag = True

        if not authflag:
            return render_json(
                None,
                {
                    "msg": "Not Authorized",
                    "code": 401,
                    "source": "Auth"
                }
            )
        else:
            return func(req, *args, **kwargs)

    return auth_wrapper


@api_url(r"")
def auth(req):
    """"""
    result = None
    err = None

    if req.method == "POST":
        if (('user' in req.POST or 'username' in req.POST) and
                ('pass' in req.POST or 'password' in req.POST)):

            uname = req.POST.get('user', default=None) or req.POST.get('username')
            passw = req.POST.get('pass', default=None) or req.POST.get('password')

            try:
                from django.contrib.auth import authenticate
                user = authenticate(username=uname, password=passw)
                if user is not None:
                    token = AuthToken(user=user)
                    digest = token.generate_token()
                    token.save()
                    result = {
                        "token": digest,
                        "expires": token.expires.isoformat(),
                    }
                else:
                    err = {
                        "msg": "Bad Username or Password",
                        "code": 403,
                        "source": "api/auth"
                    }
            except ObjectDoesNotExist:
                err = {
                    "msg": "Bad Username or Password",
                    "code": 403,
                    "source": "api/auth"
                }
        else:
            err = {
                "msg": "Bad Request, user and pass missing",
                "code": 400,
                "source": "api/auth"
            }
    else:
        err = {
            "msg": "Method Not Allowed",
            "code": 405,
            "source": "api/auth"
        }

    return render_json(result, err)



@api_url(r"")
@authorize
def expire(req):
    """"""
    result = None
    err = None

    if req.token.valid and timezone.now() < req.token.expires:
        req.token.valid = False
        result = {
            "success": True
        }
        req.token.save()
    else:
        err = {
            "msg": "Token already expired",
            "code": 409,
            "source": "api/expire"
        }

    return render_json(result, err)

@api_url(r"([0-9]+)")
@authorize
def getUser(req, user_id):
    """"""
    result = None
    err = None
    uid = int(user_id)
    user = None

    _round = req.GET.get("round", "False")
    _depth = req.GET.get("depth", "0")

    try:
        user = User.objects.get(id=uid)
    except ObjectDoesNotExist:
        pass

    if user:
        data = get_properties(user)
        data = trunate_to_ids(data)
        result = {
            "user": data
        }
    else:
        err = {
            "msg": "User does not exist",
            "code": 404,
            "source": "api/getuser"
        }

    return render_json(result, err)


@api_url(r"(\w+)/(\w+)")
@authorize
def getUserByName(req, first, last):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"(\w+)/(\w+)")
@authorize
def getResidentByName(req, first, last):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"([0-9]+)")
@authorize
def getResidentByID(req, rid):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"(.+)/(.+)")
@authorize
def getResidentByRoom(req, hall, room):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getResidentPicByName(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getResidentPicByID(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getResidentNotes(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getResidentNote(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getFormTemplateList(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getFormTemplate(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getFormData(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getRequestedForms(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getFormStatus(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getResidenceHalls(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getResidencehallByName(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getZones(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getZonesByhall(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getZone(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getNodesInZone(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getNode(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getIssues(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getIssuesByZone(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getIssue(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getIssueComments(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getIssueComment(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getRoundTemplates(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getRoundTemplate(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getRound(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def getRoundStatus(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def createResidentNote(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def editResidentNote(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def addResident(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def createForm(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def submitLockoutForm(req):
    """"""
    result = None
    err = None

    needed_keys = set(["author", "hall", "room_number", "student",  "verification_method"])
    extra_keys = set(["date", "student_sig",])

    # try:
    #     data = json.loads(req.POST.get("data", default="{}"))
    # except Exception:
    #     data = {}
    body = {}
    try:
        body = json.loads(req.body.decode('utf-8'))
    except Exception:
        pass
    data = body["data"] if "data" in body else {}

    data_keys = set(data.keys())

    if data_keys.issubset(needed_keys | extra_keys) and needed_keys.issubset(data_keys):
        try:
            form = RoomEntryRequestForm()
            author_name = data["author"].split(" ")
            form.author = RA.objects.get(first_name=author_name[0], last_name=author_name[1])
            form.hall = ResidenceHall.objects.get(name=data["hall"])
            form.room_number = data["room_number"]
            student_name = data["student"].split(" ")
            form.student = Resident.objects.get(first_name=student_name[0], last_name=student_name[1])
            # student_sig = data["student_sig"]
            form.verification_method = data["verification_method"]

            # sig = data["student_sig"]
            # print(type(sig))
            # if type(sig) is not dict:
            #     try:
            #         sig = base64.decodebytes(data["student_sig"].encode("utf-8"))
            #     except Exception:
            #         sig = bytes(b'')

            # form.student_sig = sig

            if extra_keys.issubset(data_keys):
                form.date = datetime.datetime.strptime(date["date"], "%Y-%m-%d")

            else:
                form.date = datetime.date.today()

            form.save()

            fdata = get_properties(form)
            fdata = trunate_to_ids(fdata)
            # fdata["student_sig"] = fdata["student_sig"].decode('utf-8')
            fdata["student_sig"] = None
            result = {
                "form": fdata
            }

        except ObjectDoesNotExist as e:
            err = {
                "msg": "Bad form data, objects dont't exist: {}".format(e),
                "code": 400,
                "source": "api/auth"
            }
    else:
        err = {
            "msg": "Bad form data, keys mismatch.\ngot: {} \nneed: {} \nallowed: {}".format(
                list(data_keys),
                list(needed_keys),
                list(needed_keys | extra_keys)),
            "code": 400,
            "source": "api/auth"
        }

    # author
    # hall
    # room
    # student
    # sig BASE64 string with newlines

    # TODO

    return render_json(result, err)

@api_url(r"")
@authorize
def editFormData(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def createFormTemplate(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def editFromTemplate(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def removeFormTemplate(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def createIssue(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def editIssue(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def createIssueComment(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def editIssueComment(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def createRoundData(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def editRoundData(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def searchResidentByArea(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def searchResidentByHall(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def searchResidentByName(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)


@api_url(r"")
@authorize
def searchResidentFull(req):
    """"""
    result = None
    err = None

    # TODO

    return render_json(result, err)
