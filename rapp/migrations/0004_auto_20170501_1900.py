# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2017-05-02 01:00
from __future__ import unicode_literals

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('rapp', '0003_auto_20170501_1340'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authtoken',
            name='expires',
            field=models.DateTimeField(default=datetime.datetime(2017, 5, 2, 5, 0, 10, 548595, tzinfo=utc)),
        ),
        migrations.AlterField(
            model_name='firealarm',
            name='fire_explanation',
            field=models.TextField(blank=True, default='Not a real fire', help_text='If there was an actual fire, please explain here', max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='safetyinspectionviolation',
            name='other',
            field=models.TextField(blank=True, default='None', max_length=200, null=True),
        ),
    ]