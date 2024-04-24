from django.contrib.auth.models import AbstractUser
from django.db import models


JOB_TITLE = [
    ('CEO', 'CEO'),
    ('VP', 'VP'),
    ('Executive', 'Executive'),
    ('Employee', 'Employee'),
]

ROLE = [
    ('admin', 'admin'),
    ('member', 'member'),
    ('emp', 'emp'),
]


class User(AbstractUser):
    mobile_number = models.CharField(max_length=20, null=True, blank=True)
    job_title = models.CharField(max_length=100, choices=JOB_TITLE, null=True, blank=True)
    role = models.CharField(max_length=100, choices=ROLE, null=True, blank=True)
