from django import forms
from .models import *
class TaskForm(forms.ModelForm):
    class Meta: 
        model = Task # Es REFERENCIA a una clase, no una instancia 
        fields = ['title','description','important']