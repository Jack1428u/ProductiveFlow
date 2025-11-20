# pylint: disable=E1101
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.db import OperationalError  # Para manejar el error de la db
from django.contrib.auth import login, logout, authenticate
from .forms import *
from django.utils import timezone
from django.contrib.auth.decorators import login_required
# Create your views here.


def home(request):
    return render(request, 'home.html')


def signUp(request):
    if request.method == 'GET':
        return render(request, 'signup.html', {
            'form': UserCreationForm,
        })
    else:
        if User.objects.filter(username=request.POST['username']).exists():
            return render(request, 'signup.html', {
                'form': UserCreationForm,
                'error': 'User already exists',
            })
        if request.POST['password1'] != request.POST['password2']:
            return render(request, 'signup.html', {
                'form': UserCreationForm,
                'error': 'Password do not match!',
            })
        try:
            user = User.objects.create_user(
                username=request.POST['username'],
                password=request.POST['password1'],
            )
            login(request, user)
            return render(request, 'signup.html', {
                'form': UserCreationForm,
                'error': 'User created successfully✅',
            })

        except OperationalError:  # Se intenta modificar la base de datos simultaneamente
            return render(request, 'signup.html', {
                'form': UserCreationForm,
                'error': "Database is locked",
            })


def signIn(request):
    if request.method == 'GET':
        return render(request, 'signin.html', {
            'signin': AuthenticationForm,
        })
    else:

        user = authenticate(
            request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'signin.html', {
                'signin': AuthenticationForm,
                'error': '¡The data do not match!',
            })
        else:
            login(request, user)
            return redirect('tasks')


@login_required
def signOut(request):
    logout(request)
    return redirect('home')


@login_required
def create_task(request):
    if request.method == 'GET':
        return render(request, 'create_task.html', {
            'form': TaskForm,
        })
    else:
        try:
            form = TaskForm(request.POST)  # is a form
            # is a instance of Task, commit is for save remaining data
            object_task = form.save(commit=False)
            object_task.user = request.user  # user actually login
            object_task.save()  # save of DB
            return redirect('tasks')
        except ValueError:
            return render(request, 'create_task.html', {
                'form': TaskForm,
                'error': 'Please your must enter valid data',
            })


@login_required
def tasks(request):
    # tasks = Task.objects.filter(User = request.user)
    tasks = Task.objects.filter(user=request.user, dateCompleted__isnull=True)
    return render(request, 'tasks.html', {
        'tasks': tasks,
    })
@login_required
def task_detail(request, task_id):
    task = get_object_or_404(Task, id=task_id, user=request.user)
    if request.method == 'GET':
        form = TaskForm(instance=task)
        return render(request, 'task_detail.html', {
            'task': task,
            'form': form,
        })
    else:
        try:
            form = TaskForm(request.POST, instance=task)
            form.save()
            return redirect('tasks')
        except ValueError:
            form = TaskForm(instance=task)
            return render(request, 'task_detail.html', {
                'task': task,
                'form': form,
                'error': 'Data no valid',
            })
        except OperationalError:
            form = TaskForm(instance=task)
            return render(request, 'task_detail.html', {
                'task': task,
                'form': form,
                'error': 'The database is locked',
            })

@login_required
def task_complete(request, task_id):
    if request.method == 'POST':
        task = get_object_or_404(Task, id=task_id, user=request.user)
        task.dateCompleted = timezone.now()
        task.save()
        return redirect('tasks')

@login_required
def delete_task(request, task_id):
    if request.method == 'POST':
        task = get_object_or_404(Task, id=task_id, user=request.user)
        task.delete()
        return redirect('tasks')

@login_required
def tasks_completed(request):
    # task = get_object_or_404(Task,user=request.user)
    tasks = Task.objects.filter(user=request.user, dateCompleted__isnull=False)
    return render(request, 'tasks_completed.html', {
        'tasks': tasks,
    })
