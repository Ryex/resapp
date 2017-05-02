# from inspect import signature
from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import api_funcs


ENDPOINTS = [

    # Auth

    "auth",
    "expire",

    # GET

    "getUser",
    "getUserByName",
    "getResidentByName",
    "getResidentByID",
    "getResidentByRoom",
    "getResidentPicByName",
    "getResidentPicByID",
    "getResidentNotes",
    "getResidentNote",
    "getFormTemplateList",
    "getFormTemplate",
    "getFormData",
    "getRequestedForms",
    "getFormStatus",
    "getResidenceHalls",
    "getResidencehallByName",
    "getZones",
    "getZonesByhall",
    "getZone",
    "getNodesInZone",
    "getNode",
    "getIssues",
    "getIssuesByZone",
    "getIssue",
    "getIssueComments",
    "getIssueComment",
    "getRoundTemplates",
    "getRoundTemplate",
    "getRound",
    "getRoundStatus",
    #"getRoundData",

    # POST

    "createResidentNote",
    "editResidentNote",
    "addResident",
    "createForm",
    "editFormData",
    "createFormTemplate",
    "editFromTemplate",
    "removeFormTemplate",
    "createIssue",
    "editIssue",
    "createIssueComment",
    "editIssueComment",
    "createRoundData",
    "editRoundData",
    "submitLockoutForm",

    # SEARCH

    "searchResidentByArea",
    "searchResidentByHall",
    "searchResidentByName",
    "searchResidentFull",
]

IGNORE_PARAMS = ("res",)

URL_TOP = "api"
URL_SEP = "/"

def make_url_patterns():
    """builds a list of API urls, adding their tagged params"""
    url_patterns = []

    for endpoint in ENDPOINTS:
        func = getattr(api_funcs, endpoint)
        if hasattr(func, "__urlpattern__"):
            urlpat = func.__urlpattern__.strip()
            if not urlpat:
                urlpat = "/"
            else:
                urlpat = "/{}/".format(urlpat)
            pattern = r"^{}/{}{}$".format(URL_TOP, endpoint.lower(), urlpat)
            url_patterns.append(url(pattern,  csrf_exempt(func)))
        else:
            continue
        # sig = signature(func)
        # params = []
        # for param in sig.parameters:
        #     param = str(param)
        #     if param in IGNORE_PARAMS:
        #         continue
        #     params.append(param)
        # url_pattern = r"^%/%/".format(URL_TOP, URL_SEP.join(params))
    return url_patterns
