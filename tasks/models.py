#pylint: disable=E1101
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
# Create your models here.
class Task(models.Model):
    title = models.CharField(max_length=12)
    description = models.TextField(max_length=50, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    dateCompleted = models.DateTimeField(null=True)
    important = models.BooleanField(default=False)
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    def __str__(self):
        txt = "Task: {0:<16} | Date Created: {1:<16} |  Adviser: {2:<16}"
        return txt.format(self.title.title(),self.created,self.user.username.capitalize())