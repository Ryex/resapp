# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2017-05-01 02:46
from __future__ import unicode_literals

import datetime
from django.conf import settings
import django.contrib.postgres.fields
import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion
from django.utils.timezone import utc


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AuthToken',
            fields=[
                ('token', models.CharField(db_index=True, max_length=64, primary_key=True, serialize=False, unique=True)),
                ('issued', models.DateTimeField(auto_now_add=True)),
                ('expires', models.DateTimeField(default=datetime.datetime(2017, 5, 1, 6, 46, 41, 99006, tzinfo=utc))),
                ('valid', models.BooleanField(default=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='BuildingZone',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('vectors', django.contrib.postgres.fields.ArrayField(base_field=django.contrib.postgres.fields.ArrayField(base_field=django.contrib.postgres.fields.ArrayField(base_field=models.IntegerField(), size=None), size=None), size=None)),
                ('gps', django.contrib.postgres.fields.ArrayField(base_field=models.IntegerField(), size=None)),
                ('parent', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='rapp.BuildingZone')),
            ],
        ),
        migrations.CreateModel(
            name='BuildingZoneLabel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('location', django.contrib.postgres.fields.ArrayField(base_field=models.IntegerField(), size=None)),
                ('link', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='link', to='rapp.BuildingZone')),
                ('zone', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='zone', to='rapp.BuildingZone')),
            ],
        ),
        migrations.CreateModel(
            name='BuildingZoneNode',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(max_length=1000)),
                ('location', django.contrib.postgres.fields.ArrayField(base_field=models.IntegerField(), size=None)),
                ('check', models.BooleanField()),
                ('zone', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rapp.BuildingZone')),
            ],
        ),
        migrations.CreateModel(
            name='ConditionReport',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('edited', models.DateTimeField(auto_now=True)),
                ('images', django.contrib.postgres.fields.ArrayField(base_field=models.IntegerField(), size=None)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='author', to=settings.AUTH_USER_MODEL)),
                ('editedby', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='editedby', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='FireAlarm',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('room_number', models.CharField(blank=True, max_length=10, null=True)),
                ('date', models.DateTimeField(null=True)),
                ('occurence_time', models.TimeField(null=True, verbose_name='Time of the incident')),
                ('specific_location', models.TextField(max_length=50, null=True, verbose_name='Specific location of the incident')),
                ('cause', models.CharField(choices=[('PULL_BOX', 'Pull Box'), ('HEAT', 'Heat Detector'), ('SMOKE', 'Smoke Detector'), ('MALFUNCTION', 'Malfunction'), ('DRILL', 'Fire Drill'), ('UNKNOWN', 'Unknown'), ('FIRE', 'Fire')], max_length=20, null=True)),
                ('fire_explanation', models.TextField(blank=True, help_text='If there was an actual fire, please explain here', max_length=200, null=True)),
                ('other_ras', models.TextField(default='none', max_length=500, null=True, verbose_name='Other RAs involved or present')),
                ('notes', models.TextField(blank=True, max_length=500, null=True, verbose_name='Additional notes')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='FormData',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('edited', models.DateTimeField(auto_now=True)),
                ('status', models.CharField(choices=[('IN', 'Incompleate'), ('CO', 'Compleate')], max_length=2)),
                ('data', django.contrib.postgres.fields.jsonb.JSONField()),
                ('images', django.contrib.postgres.fields.ArrayField(base_field=models.IntegerField(), size=None)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('editedby', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='formdata_editedby', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='FormTemplate',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('edited', models.DateTimeField(auto_now=True)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('editedby', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='formtemplate_editedby', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='FromTemplateData',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('template', models.TextField(max_length=1000)),
                ('pairs', django.contrib.postgres.fields.jsonb.JSONField()),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('from_template', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rapp.FormTemplate')),
            ],
        ),
        migrations.CreateModel(
            name='Issue',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('edited', models.DateTimeField(auto_now=True)),
                ('content', models.TextField(max_length=1000)),
                ('status', models.CharField(choices=[('OP', 'Open'), ('CL', 'Closed'), ('IN', 'Invalid'), ('NO', 'No Fix')], max_length=2)),
                ('images', django.contrib.postgres.fields.ArrayField(base_field=models.IntegerField(), size=None)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('editedby', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='issue_editedby', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='IssueComment',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('edited', models.DateTimeField(auto_now=True)),
                ('content', models.TextField(max_length=1000)),
                ('images', django.contrib.postgres.fields.ArrayField(base_field=models.IntegerField(), size=None)),
                ('access', models.ManyToManyField(related_name='issuecomment_access', to=settings.AUTH_USER_MODEL)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('editedby', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='issuecomment_editedby', to=settings.AUTH_USER_MODEL)),
                ('issue', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rapp.Issue')),
            ],
        ),
        migrations.CreateModel(
            name='LogAction',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('action', models.CharField(max_length=100)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('detail', models.TextField(max_length=1000)),
                ('type', models.CharField(max_length=100)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Note',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('top', models.BooleanField(default=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('edited', models.DateTimeField(auto_now=True)),
                ('content', models.TextField(max_length=1000)),
                ('access', models.ManyToManyField(related_name='note_access', to=settings.AUTH_USER_MODEL)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ProgramPacket',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('room_number', models.CharField(blank=True, max_length=10, null=True)),
                ('date', models.DateTimeField(null=True)),
                ('program_title', models.TextField(max_length=100, null=True)),
                ('program_date', models.DateField(null=True)),
                ('program_time', models.TimeField(null=True)),
                ('location1', models.TextField(max_length=50, null=True, verbose_name='First choice location')),
                ('space_need_reservation1', models.BooleanField(verbose_name='(First choice) reservation needed?')),
                ('reservation_made1', models.BooleanField(verbose_name='(First choice) reservation made')),
                ('location2', models.TextField(max_length=50, null=True, verbose_name='Second choice location')),
                ('space_need_reservation2', models.BooleanField(verbose_name='(Second choice) reservation needed?')),
                ('reservation_made2', models.BooleanField(verbose_name='(Second choice) reservation made')),
                ('target_audience', models.TextField(max_length=200, null=True)),
                ('advertising', models.TextField(max_length=200, null=True, verbose_name='Advertising method')),
                ('coordinator_approval', models.BooleanField(default=False, verbose_name='Coordinator approval')),
                ('sig_date', models.DateField(null=True, verbose_name='Signed date')),
                ('program_description', models.TextField(max_length=500, null=True)),
                ('supplies', models.TextField(max_length=300, null=True, verbose_name='Supplies needed')),
                ('proposed_cost', models.PositiveIntegerField(null=True, verbose_name='Proposed cost (to the nearest dollar)')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='RA',
            fields=[
                ('first_name', models.CharField(max_length=100)),
                ('last_name', models.CharField(max_length=100)),
                ('date_of_birth', models.DateField(blank=True, null=True)),
                ('student_id', models.PositiveIntegerField(primary_key=True, serialize=False, unique=True, verbose_name='900 Number')),
                ('student_email', models.EmailField(default='firstname.lastname@student.nmt.edu', max_length=100, verbose_name='NMT Email')),
                ('emergency_contact', models.CharField(blank=True, default='none given', max_length=40)),
                ('contact_relationship', models.CharField(blank=True, default='none given', max_length=100)),
                ('emergency_contact_phone', models.CharField(default='(123) 456-7890', max_length=30, verbose_name='Emergency Contact Phone Number')),
                ('home_addr', models.TextField(blank=True, default='none given', max_length=100, verbose_name='Home Address')),
                ('car_plate', models.CharField(blank=True, default='none given', max_length=20)),
                ('car_info', models.TextField(blank=True, default='none given', help_text='Make/model/description of car', max_length=100)),
                ('room_number', models.CharField(max_length=10, null=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='ResidenceHall',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, null=True)),
                ('rlc', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, verbose_name='Residential Life Coordinator')),
            ],
        ),
        migrations.CreateModel(
            name='Resident',
            fields=[
                ('first_name', models.CharField(max_length=100)),
                ('last_name', models.CharField(max_length=100)),
                ('date_of_birth', models.DateField(blank=True, null=True)),
                ('student_id', models.PositiveIntegerField(primary_key=True, serialize=False, unique=True, verbose_name='900 Number')),
                ('student_email', models.EmailField(default='firstname.lastname@student.nmt.edu', max_length=100, verbose_name='NMT Email')),
                ('emergency_contact', models.CharField(blank=True, default='none given', max_length=40)),
                ('contact_relationship', models.CharField(blank=True, default='none given', max_length=100)),
                ('emergency_contact_phone', models.CharField(default='(123) 456-7890', max_length=30, verbose_name='Emergency Contact Phone Number')),
                ('home_addr', models.TextField(blank=True, default='none given', max_length=100, verbose_name='Home Address')),
                ('car_plate', models.CharField(blank=True, default='none given', max_length=20)),
                ('car_info', models.TextField(blank=True, default='none given', help_text='Make/model/description of car', max_length=100)),
                ('room_number', models.CharField(max_length=10, null=True)),
                ('RA', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='rapp.RA')),
                ('hall', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='rapp.ResidenceHall', verbose_name='Residence Hall')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Room',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('max_residents', models.IntegerField()),
                ('name', models.CharField(max_length=100)),
                ('hall', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rapp.ResidenceHall')),
            ],
        ),
        migrations.CreateModel(
            name='RoomEntryRequestForm',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('room_number', models.CharField(blank=True, max_length=10, null=True)),
                ('date', models.DateTimeField(null=True)),
                ('student_sig', models.BinaryField(default=0, verbose_name='Resident signature image')),
                ('verification_method', models.TextField(max_length=40, null=True)),
                ('author', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='rapp.RA')),
                ('hall', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='rapp.ResidenceHall', verbose_name='Residence Hall')),
                ('student', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='rapp.Resident', verbose_name='Resident name')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='RoundArea',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('zones', models.ManyToManyField(to='rapp.BuildingZone')),
            ],
        ),
        migrations.CreateModel(
            name='RoundData',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('edited', models.DateTimeField(auto_now=True)),
                ('status', models.CharField(choices=[('IN', 'Incompleate'), ('CO', 'Compleate')], max_length=2)),
                ('data', django.contrib.postgres.fields.jsonb.JSONField()),
                ('images', django.contrib.postgres.fields.ArrayField(base_field=models.IntegerField(), size=None)),
                ('area', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rapp.RoundArea')),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('editedby', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='rounddata_editedby', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='SafetyInspectionViolation',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('room_number', models.CharField(blank=True, max_length=10, null=True)),
                ('date', models.DateTimeField(null=True)),
                ('prohibited_appliances', models.BooleanField(default=False)),
                ('candle_incense', models.BooleanField(default=False, verbose_name='Candles or incense')),
                ('extension_cords', models.BooleanField(default=False)),
                ('lounge_furniture', models.BooleanField(default=False, verbose_name='Lounge furniture in room')),
                ('trash_violation', models.BooleanField(default=False)),
                ('animals', models.BooleanField(default=False)),
                ('alcohol_drugs', models.BooleanField(default=False, verbose_name='Alcohol or drugs')),
                ('fire_safety', models.BooleanField(default=False)),
                ('other', models.TextField(blank=True, max_length=200, null=True)),
                ('sig', models.BinaryField(default=0, verbose_name='Student signature')),
                ('additional_action', models.BooleanField(default=False, verbose_name='Additional action required')),
                ('author', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='rapp.RA')),
                ('hall', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='rapp.ResidenceHall', verbose_name='Residence Hall')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.AddField(
            model_name='ra',
            name='hall',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='rapp.ResidenceHall', verbose_name='Residence Hall'),
        ),
        migrations.AddField(
            model_name='ra',
            name='user',
            field=models.OneToOneField(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='programpacket',
            name='author',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='rapp.RA'),
        ),
        migrations.AddField(
            model_name='programpacket',
            name='coordinator_sig',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, verbose_name='Signing RLC'),
        ),
        migrations.AddField(
            model_name='programpacket',
            name='hall',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='rapp.ResidenceHall', verbose_name='Residence Hall'),
        ),
        migrations.AddField(
            model_name='note',
            name='resident',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rapp.Resident'),
        ),
        migrations.AddField(
            model_name='issue',
            name='node',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rapp.RoundArea'),
        ),
        migrations.AddField(
            model_name='formtemplate',
            name='templatedata',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rapp.FromTemplateData'),
        ),
        migrations.AddField(
            model_name='formdata',
            name='template',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rapp.FromTemplateData'),
        ),
        migrations.AddField(
            model_name='firealarm',
            name='author',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='rapp.RA'),
        ),
        migrations.AddField(
            model_name='firealarm',
            name='hall',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='rapp.ResidenceHall', verbose_name='Residence Hall'),
        ),
        migrations.AddField(
            model_name='conditionreport',
            name='resident',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rapp.Resident'),
        ),
        migrations.AddField(
            model_name='conditionreport',
            name='room',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rapp.Room'),
        ),
    ]
