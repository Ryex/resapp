from django.conf.urls import url
from . import views
from . import api

urlpatterns = [
    url(r'^$', views.dashboard, name='dashboard'),
    url(r'^$', views.logout, name='logout'),
    url(r'^statistics/$', views.stats, name='stats'),
    url(r'^room_entry_requests/$', views.RoomEntryRequestList, name='room_entry_requests'),
    url(r'^program_packets/$', views.ProgramPacketList, name='program_packets'),
    url(r'^safety_inspections/$', views.SafetyInspectionViolationList, name='safety_inspections'),
    url(r'^fire_alarms/$', views.FireAlarmList, name='fire_alarms'),
    url(r'^ra_list/$', views.ra_list, name='ra_list'),
#    url(r'^halls/(?P<pk>\d+)/$', views.halls_list, name='halls'),
#    url(r'^roominspection/(?P<pk>\d+)/$', views.form_detail, name='form_detail'),
#    url(r'^ra/(?P<pk>\d+)/$', views.form_detail, name='form_detail'),
    url(r'^student_profile/(?P<pk>\d+)/$', views.student_profile, name='student_profile'),
]

urlpatterns.extend(api.make_url_patterns())
