import datetime
import hashlib
import hmac
import base64
import django
from django.db import models
from django import forms
from django.utils import timezone
from django.core.mail import send_mail
from django.contrib import postgres
from django.core.signing import Signer
import django.contrib.postgres.fields #force the module to load
from django.conf import settings

#############################################
# STUDENT CLASSES #
#############################################
class StudentBase(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    date_of_birth = models.DateField(null=True, blank=True)
    student_id = models.PositiveIntegerField(primary_key=True, unique=True, verbose_name="900 Number")
    student_email = models.EmailField(max_length=100, default="firstname.lastname@student.nmt.edu", verbose_name="NMT Email")
    emergency_contact = models.CharField(max_length=40, default='none given', blank=True)
    contact_relationship = models.CharField(max_length=100, default='none given', blank=True)
    emergency_contact_phone = models.CharField(default='(123) 456-7890', max_length=30, verbose_name="Emergency Contact Phone Number")
    home_addr = models.TextField(max_length=100, default='none given', blank=True, verbose_name="Home Address")
    car_plate = models.CharField(max_length=20, default='none given', blank=True)
    car_info = models.TextField(max_length=100, help_text="Make/model/description of car", default='none given', blank=True)

    class Meta:
        abstract = True

class Resident(StudentBase):
    hall = models.ForeignKey('ResidenceHall', null=True, on_delete=models.SET_NULL, verbose_name="Residence Hall")
    room_number = models.CharField(max_length=10, null=True)
    RA = models.ForeignKey('RA', null=True, on_delete=models.SET_NULL)

    def __str__(self):
        return '%s %s' % (self.first_name, self.last_name)

class RA(StudentBase):
    hall = models.ForeignKey('ResidenceHall', null=True, on_delete=models.SET_NULL, verbose_name="Residence Hall")
    room_number = models.CharField(max_length=10, null=True)
    user = models.OneToOneField('auth.user', null=True, on_delete=models.SET_NULL)

    def __str__(self):
        return '%s %s' % (self.first_name, self.last_name)

class ResidenceHall(models.Model):
    name = models.CharField(null=True, max_length=100)
    rlc = models.ForeignKey('auth.user', verbose_name="Residential Life Coordinator")

    def __str__(self):
        return '%s' % (self.name)

#############################################
# FORM CLASSES #
#############################################

#base ABSTRACT form class
class FormBase(models.Model):
    author = models.ForeignKey('RA', null=True)
    hall = models.ForeignKey('ResidenceHall', null=True, verbose_name="Residence Hall")
    date = models.DateTimeField(null=True)

    class Meta:
        abstract = True

class RoomEntryRequestForm(FormBase):
    room_number = models.CharField(null=True, max_length=10)
    student = models.ForeignKey('Resident', null=True, on_delete=models.SET_NULL, verbose_name="Resident name")
    student_sig = models.BinaryField(verbose_name="Resident signature image")
    verification_method = models.TextField(null=True, max_length=40)

    def send_copy(self):
        send_mail('Hello!')

    def __str__(self):
        return '%s %s Room Entry Request on %s' % (self.student.first_name, self.student.last_name, self.date)

class ProgramPacket(FormBase):
    program_title = models.TextField(null=True, max_length=100)
    program_date = models.DateField(null=True)
    program_time = models.TimeField(null=True)
    location1 = models.TextField(max_length=50, null=True, verbose_name="First choice location")
    space_need_reservation1 = models.BooleanField(verbose_name="(First choice) reservation needed?")
    reservation_made1 = models.BooleanField(verbose_name="(First choice) reservation made")
    location2 = models.TextField(null=True, max_length=50, verbose_name="Second choice location")
    space_need_reservation2 = models.BooleanField(verbose_name="(Second choice) reservation needed?")
    reservation_made2 = models.BooleanField(verbose_name="(Second choice) reservation made")
    target_audience = models.TextField(null=True, max_length=200)
    advertising = models.TextField(null=True, max_length=200, verbose_name="Advertising method")
    coordinator_approval = models.BooleanField(default=False, verbose_name="Coordinator approval")
    coordinator_sig = models.ForeignKey('auth.user', blank=True, verbose_name="Signing RLC", null=True)
    sig_date = models.DateField(null=True, blank=True, verbose_name="Signed date")
    program_description = models.TextField(null=True, max_length=500)
    supplies = models.TextField(null=True, max_length=300, verbose_name="Supplies needed")
    proposed_cost = models.PositiveIntegerField(null=True, verbose_name="Proposed cost (to the nearest dollar)")

    @property
    def approved(self):
        if self.coordinator_approval == True:
            return True
        return False

    def __str__(self):
        return '%s Program Packet from %s submitted on %s' % (self.program_title, self.author, self.date)

class SafetyInspectionViolation(FormBase):
    room_number = models.CharField(null=True, max_length=10)
    prohibited_appliances = models.BooleanField(default=False)
    candle_incense = models.BooleanField(default=False, verbose_name="Candles or incense")
    extension_cords = models.BooleanField(default=False)
    lounge_furniture = models.BooleanField(default=False, verbose_name="Lounge furniture in room")
    trash_violation = models.BooleanField(default=False)
    animals = models.BooleanField(default=False)
    alcohol_drugs = models.BooleanField(default=False, verbose_name="Alcohol or drugs")
    fire_safety = models.BooleanField(default=False)
    other = models.TextField(null=True, max_length=200, default='None', blank=True)
    sig = models.BinaryField(verbose_name="Student signature")
    additional_action = models.BooleanField(default=False, verbose_name="Additional action required")

    def __str__(self):
        return 'Inspection Violation - %s %s' % (self.hall, self.room_number)

class FireAlarm(FormBase):
    occurence_time = models.TimeField(null=True, verbose_name="Time of the incident")
    specific_location = models.TextField(null=True, max_length=50, verbose_name="Specific location of the incident")
    ALARM_CAUSES = (
        ('PULL_BOX', 'Pull Box'),
        ('HEAT', 'Heat Detector'),
        ('SMOKE', 'Smoke Detector'),
        ('MALFUNCTION', 'Malfunction'),
        ('DRILL', 'Fire Drill'),
        ('UNKNOWN', 'Unknown'),
        ('FIRE', 'Fire')
    )
    cause = models.CharField(choices=ALARM_CAUSES, null=True, max_length=20)
    fire_explanation = models.TextField(default='Not a real fire', max_length=200, null=True, blank=True, help_text="If there was an actual fire, please explain here")
    other_ras = models.TextField(max_length=500, null=True, default="none", verbose_name="Other RAs involved or present")
    notes = models.TextField(max_length=500, null=True, blank=True, verbose_name="Additional notes")

    def __str__(self):
        return '%s Fire Alarm on %s' % (self.hall, self.date)

#############################################
# API
#############################################

class Room(models.Model):
    id = models.AutoField(primary_key=True)
    hall = models.ForeignKey("ResidenceHall")
    max_residents = models.IntegerField()
    name = models.CharField(max_length=100)

    def is_full(self):
        # return via it's back relation if the room is full
        pass

    def free(self):
        # return via back relation and max_residents the number of free slots
        pass

    def valid(self):
        # if there are free slots or the room is full the room is valid, if the room is OVER full it's is invalid
        pass


class ConditionReport(models.Model):
    id = models.AutoField(primary_key=True)
    room = models.ForeignKey("Room")
    resident = models.ForeignKey("Resident")
    author = models.ForeignKey('auth.user', related_name='author')
    created = models.DateTimeField(auto_now_add=True)
    edited = models.DateTimeField(auto_now=True)
    editedby = models.ForeignKey('auth.user', related_name='editedby')
    images = postgres.fields.ArrayField(base_field=models.IntegerField())

    def empty(self):
        # return via back relation if no residents are assigned to the room
        pass


def valid_base64_sha(value):
    '''
    base64 decode the data and check if it's 32 bytes.

    tokens are encoded sha256 hashes
    sha256 hashes are always 256 bits or 32 bytes long

    checking if the data encoded in a token decodes as valid base64
    and containes 32 bytes should be suffecient
    '''
    try:
        if value:
            return len(base64.urlsafe_b64decode(value)) == 32
        return False
    except base64.binascii.Error:
        return False

def validate_token(value):
    if not valid_base64_sha(value):
        raise django.core.exceptions.ValidationError(
            '%(value)s is not a valid base64 encoded sha',
            params={'value': value}
        )



class AuthToken(models.Model):
    token = models.CharField(primary_key=True, max_length=64, unique=True, db_index=True, validators=[validate_token])
    user = models.ForeignKey('auth.user')
    issued = models.DateTimeField(null=False)
    expires = models.DateTimeField(null=False)
    valid = models.BooleanField(default=True)

    def generate_token(self):
        '''issued = isoformat timestamp'''
        self.clean_fields(exclude=('token', 'issued', 'expires'))
        signer = Signer()
        if not self.issued:
            self.set_issue_time()
        mac = self.user.username + self.issued.isoformat()
        signed_mac = signer.sign(mac)
        token = hashlib.sha256(signed_mac.encode('utf-8'))
        digest = base64.urlsafe_b64encode(token.digest())
        self.token = digest.decode("utf-8")
        return self.token

    def set_issue_time(self, time=None):
        '''If time is not provided or is the wrong type defaults to now'''
        if type(time) is not datetime.datetime:
            time = timezone.now()
        self.issued = time
        self.expires = time + datetime.timedelta(hours=settings.TOKEN_AUTH_HOURS)

    def save(self, *args, **kwargs):
        """force the model to validate on save."""
        self.full_clean()
        super(AuthToken, self).save(*args, **kwargs)



class Note(models.Model):
    id = models.AutoField(primary_key=True)
    top = models.BooleanField(default=False)
    resident = models.ForeignKey('Resident')
    author = models.ForeignKey('auth.user')
    created = models.DateTimeField(auto_now_add=True)
    edited = models.DateTimeField(auto_now=True)
    content = models.TextField(max_length=1000)  # TODO perhaps be json field
    comments = postgres.fields.ArrayField(base_field=models.IntegerField)  # Access through back related set
    access = models.ManyToManyField("auth.user", related_name='note_access')
    #access_level = models.CharField(max_length=2, choices=auth.user.ACCESS_LEVELS, default=auth.user.RA)

#############################################
# UNUSED For later Template system
#############################################
class FormTemplate(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    author = models.ForeignKey('auth.user')
    created = models.DateTimeField(auto_now_add=True)
    edited = models.DateTimeField(auto_now=True)
    editedby = models.ForeignKey('auth.user', related_name='formtemplate_editedby')
    templatedata = models.ForeignKey('FromTemplateData')
    versions = postgres.fields.ArrayField(base_field=models.IntegerField) # Access through back related set

    def __str__(self):
        return '%s' % (self.name)


class FromTemplateData(models.Model):
    id = models.AutoField(primary_key=True)
    created = models.DateTimeField(auto_now_add=True)
    author = models.ForeignKey('auth.user')
    from_template = models.ForeignKey('FormTemplate')
    template = models.TextField(max_length=1000)
    pairs = postgres.fields.JSONField()  # JSON pairs of names to types


class FormData(models.Model):

    INCOMPLEATE = "IN"
    COMPLEATE = "CO"

    STATUSES = (
        ("IN", "Incompleate"),
        ("CO", "Compleate")
    )

    id = models.AutoField(primary_key=True)
    author = models.ForeignKey('auth.user')
    created = models.DateTimeField(auto_now_add=True)
    edited = models.DateTimeField(auto_now=True)
    editedby = models.ForeignKey('auth.user', related_name='formdata_editedby')
    template = models.ForeignKey('FromTemplateData')
    status = models.CharField(max_length=2, choices=STATUSES)
    data = postgres.fields.JSONField()  # json keyvalue pairs
    images = postgres.fields.ArrayField(base_field=models.IntegerField())

#############################################
# Round and Issue system
#############################################

class BuildingZone(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    vectors = postgres.fields.ArrayField(
                base_field=postgres.fields.ArrayField(
                    base_field=postgres.fields.ArrayField(
                        base_field=models.IntegerField()
                    )
                )
            )
    parent = models.ForeignKey('BuildingZone', null=True,)
    # children = [areaid, areaid areaid, ...]
    gps = postgres.fields.ArrayField(base_field=models.IntegerField())

    def __str__(self):
        return '%s' % (self.name)

    def get_check_nodes(self):
        #return list of nodes with check flag. (for determining round data compleateness)
        pass

    def get_issue_nodes(self, resolved=False, limit=None):
        #return list of nodes without check flag that have current issues
        #include resolved issues if "resolved" is true
        #limit search to issues newer than "limit" date
        pass


class BuildingZoneNode(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    description = models.TextField(max_length=1000)
    zone = models.ForeignKey('BuildingZone')
    location = postgres.fields.ArrayField(base_field=models.IntegerField())
    check = models.BooleanField()

    def __str__(self):
        return '%s' % (self.name)


class BuildingZoneLabel(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    zone = models.ForeignKey('BuildingZone', related_name='zone')
    link = models.ForeignKey('BuildingZone', related_name='link')
    location = postgres.fields.ArrayField(base_field=models.IntegerField())

    def __str__(self):
        return '%s' % (self.name)


class RoundArea(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    zones = models.ManyToManyField('BuildingZone') # TODO does it need to include all areas or just toplevels?

    def __str__(self):
        return '%s' % (self.name)

    def get_check_nodes(self):
        #return list of nodes with check flag. (for determining round data compleateness)
        pass

    def get_issue_nodes(self, resolved=False, limit=None):
        #return list of nodes without check flag that have current issues
        #include resolved issues if "resolved" is true
        #limit search to issues newer than "limit" date
        pass


class Issue(models.Model):

    OPEN = "OP"
    CLOSED = "CL"
    INVALID = "IN"
    NO_FIX = "NO"

    STATUSES = (
        ("OP", "Open"),
        ("CL", "Closed"),
        ("IN", "Invalid"),
        ("NO", "No Fix")
    )

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    author = models.ForeignKey('auth.user')
    created = models.DateTimeField(auto_now_add=True)
    edited = models.DateTimeField(auto_now=True)
    editedby = models.ForeignKey('auth.user', related_name='issue_editedby')
    content = models.TextField(max_length=1000)
    node = models.ForeignKey('RoundArea')
    status = models.CharField(max_length=2, choices=STATUSES)
    comments = postgres.fields.ArrayField(base_field=models.IntegerField) # Access through back related set
    images = postgres.fields.ArrayField(base_field=models.IntegerField())

    def __str__(self):
        return '%s' % (self.name)


class IssueComment(models.Model):
    id = models.AutoField(primary_key=True)
    issue = models.ForeignKey('Issue')
    author = models.ForeignKey('auth.user')
    created = models.DateTimeField(auto_now_add=True)
    edited = models.DateTimeField(auto_now=True)
    editedby = models.ForeignKey('auth.user', related_name='issuecomment_editedby')
    content = models.TextField(max_length=1000)
    comments = postgres.fields.ArrayField(base_field=models.IntegerField) # Access through back related set
    access = models.ManyToManyField("auth.user", related_name='issuecomment_access')
    #access_level = models.CharField(max_length=2, choices=auth.user.ACCESS_LEVELS, default=auth.user.RA)
    images = postgres.fields.ArrayField(base_field=models.IntegerField())


class RoundData(models.Model):

    INCOMPLEATE = "IN"
    COMPLEATE = "CO"

    STATUSES = (
        ("IN", "Incompleate"),
        ("CO", "Compleate")
    )

    id = models.AutoField(primary_key=True)
    author = models.ForeignKey('auth.user')
    created = models.DateTimeField(auto_now_add=True)
    edited = models.DateTimeField(auto_now=True)
    editedby = models.ForeignKey('auth.user', related_name='rounddata_editedby')
    area = models.ForeignKey('RoundArea')
    status = models.CharField(max_length=2, choices=STATUSES)
    data = postgres.fields.JSONField()  # json keyvalue pairs
    images = postgres.fields.ArrayField(base_field=models.IntegerField())


#############################################
# Store image path
#############################################

class Image:
    id = models.AutoField(primary_key=True)
    url = models.CharField(max_length=400)


#############################################
# LogAction
#############################################
class LogAction(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey('auth.user')
    action = models.CharField(max_length=100)  # quick action summery, 2-4 words
    timestamp = models.DateTimeField(auto_now_add=True)
    detail = models.TextField(max_length=1000)
    type = models.CharField(max_length=100)  # the object type affected
