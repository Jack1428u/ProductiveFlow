from django.contrib import admin
from .models import *

class TaskAdmin(admin.ModelAdmin):
    readonly_fields = ("created",) # Tupla para evitar cambios accidentales 

# Register your models here.
admin.site.register(Task, TaskAdmin)