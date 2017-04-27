# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-04-25 16:29
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rapp', '0009_auto_20170421_2216'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='roomentryrequestform',
            name='ra_sig',
        ),
        migrations.AlterField(
            model_name='firealarm',
            name='notes',
            field=models.TextField(blank=True, max_length=500),
        ),
        migrations.RemoveField(
            model_name='firealarm',
            name='other_ras',
        ),
        migrations.AddField(
            model_name='firealarm',
            name='other_ras',
            field=models.TextField(default='none', max_length=500),
        ),
    ]