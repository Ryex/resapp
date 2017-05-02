from django.shortcuts import render, get_object_or_404
from .models import Resident, RA, ResidenceHall, RoomEntryRequestForm, ProgramPacket, SafetyInspectionViolation, FireAlarm
from django.utils import timezone
from django.contrib.auth.models import User, Group

#return ONE instance
#def form_detail(request, pk):
#    form = get_object_or_404(RoomInspectionForm, pk=pk)
#    return render(request, 'rapp/form_detail.html', {'form': form}) 

def dashboard(request):
    return render(request, 'rapp/dashboard.html')

def RoomEntryRequestList(request):
    forms = RoomEntryRequestForm.objects.all().order_by('-date')
    return render(request, 'rapp/room_entry_list.html', {'forms': forms, 'page_name': "Room Entry Request Forms"})

def ProgramPacketList(request):
    forms = ProgramPacket.objects.all().order_by('-date')
    return render(request, 'rapp/program_packets_list.html', {'forms': forms, 'page_name': "Program Packets"})

def SafetyInspectionViolationList(request):
    forms = SafetyInspectionViolation.objects.all().order_by('-date')
    return render(request, 'rapp/safety_inspection_list.html', {'forms': forms, 'page_name': "Safety Violation Reports"})

def FireAlarmList(request):
    forms = FireAlarm.objects.all().order_by('-date')
    return render(request, 'rapp/fire_alarms_list.html', {'forms': forms, 'page_name': "Fire Alarm Reports"})

def halls_list(request, pk):
    students = Resident.objects.filter(hall__pk=pk)
    return render(request, 'rapp/residence_hall.html', {'students': students}) 

def ra_list(request):
    ras = RA.objects.all()
    return render(request, 'rapp/ra_list.html', {'ras': ras})

def logout(request):
    return render(request, 'rapp/logout.html')

def logged_out(request):
    return render(request, 'rapp/logged_out.html')

#statistics page
def stats(request):
    return render(request, 'rapp/statistics.html')

#return ONE instance
def student_profile(request, pk):
    student = get_object_or_404(Student, pk=pk)
    return render(request, 'rapp/student_profile.html', {'student': student}) 
