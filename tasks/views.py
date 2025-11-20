# pylint: disable=E1101
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.db import OperationalError  # Para manejar el error de la db
from django.db.utils import IntegrityError
from django.contrib.auth import login, logout, authenticate
from .forms import *
from django.utils import timezone
from django.contrib.auth.decorators import login_required
import logging

logger = logging.getLogger(__name__)


def home(request):
    return render(request, 'home.html')


def signUp(request):
    if request.method == 'GET':
        return render(request, 'signup.html', {
            'form': UserCreationForm,
        })
    else:
        # CAMBIO 3: Extraer datos POST en una sola variable para evitar repetición
        username = request.POST.get('username', '').strip()
        password1 = request.POST.get('password1', '')
        password2 = request.POST.get('password2', '')

        # CAMBIO 4: Validar que los campos requeridos existan
        if not all([username, password1, password2]):
            logger.warning(
                f"Intento de registro con campos faltantes desde IP: {request.META.get('REMOTE_ADDR')}"
            )
            return render(request, 'signup.html', {
                'form': UserCreationForm,
                'error': 'Missing required fields',
            })

        # CAMBIO 5: Verificar si el usuario ya existe (usar exists() es más eficiente)
        if User.objects.filter(username=username).exists():
            logger.warning(
                f"Intento de registro con usuario duplicado: {username} desde IP: {request.META.get('REMOTE_ADDR')}"
            )
            return render(request, 'signup.html', {
                'form': UserCreationForm,
                'error': 'User already exists',
            })

        # CAMBIO 6: Validar que las contraseñas coincidan
        if password1 != password2:
            logger.warning(
                f"Intento de registro con contraseñas no coincidentes para usuario: {username} desde IP: {request.META.get('REMOTE_ADDR')}"
            )
            return render(request, 'signup.html', {
                'form': UserCreationForm,
                'error': 'Password do not match!',
            })

        try:
            # CAMBIO 7: Crear usuario con try-except específicos
            user = User.objects.create_user(
                username=username,
                password=password1,
            )
            logger.info(
                f"Nuevo usuario registrado exitosamente: {username} desde IP: {request.META.get('REMOTE_ADDR')}"
            )
            login(request, user)
            return redirect('tasks')

        except OperationalError as e:
            # CAMBIO 8: Capturar como 'e' y registrar el error específico
            logger.error(
                f"Error operacional de base de datos durante registro de usuario: {username}",
                exc_info=True
            )
            return render(request, 'signup.html', {
                'form': UserCreationForm,
                'error': "Database is locked",
            })

        except IntegrityError as e:
            logger.warning(
                f"Intento de crear usuario con datos duplicados: {username}",
                exc_info=True
            )
            return render(request, 'signup.html', {
                'form': UserCreationForm,
                'error': 'User already exists',
            })

        except KeyError as e:
            logger.error(
                f"Campo requerido faltante durante registro: {e}",
                exc_info=True
            )
            return render(request, 'signup.html', {
                'form': UserCreationForm,
                'error': 'Missing required fields',
            })

        except Exception as e:
            logger.error(
                f"Error inesperado durante registro de usuario: {username}",
                exc_info=True
            )
            return render(request, 'signup.html', {
                'form': UserCreationForm,
                'error': 'Error creating user',
            })


def signIn(request):
    if request.method == 'GET':
        return render(request, 'signin.html', {
            'signin': AuthenticationForm,
        })
    else:
        try:
            username = request.POST['username']
            password = request.POST['password']
        except KeyError:
            # Registrar intento con datos faltantes
            logger.warning(
                f"Intento de login sin credenciales completas desde IP: {request.META.get('REMOTE_ADDR')}")
            return render(request, 'signin.html', {
                'signin': AuthenticationForm,
                'error': 'Username and password required',
            })

        try:
            user = authenticate(
                request, username=request.POST['username'], password=request.POST['password']
            )
            if user is None:
                # Registrar intento fallido de autenticación (sin exponer contraseña)
                logger.warning(
                    f"Intento de login fallido para usuario: {username} desde IP: {request.META.get('REMOTE_ADDR')}")
                return render(request, 'signin.html', {
                    'signin': AuthenticationForm,
                    'error': '¡The data do not match!',
                })
            else:
                # Registrar login exitoso
                logger.info(
                    f"Login exitoso para usuario: {username} desde IP: {request.META.get('REMOTE_ADDR')}")
                login(request, user)
                return redirect('tasks')
        # CAMBIO 6: Cambiar 'as _' a 'as e' para capturar la excepción
        except Exception as _:
            # Registrar el error completo con stack trace para debugging
            logger.error(
                f"Error inesperado en autenticación para usuario: {username} desde IP: {request.META.get('REMOTE_ADDR')}",
                exc_info=True  # Incluye el stack trace completo
            )
            return render(request, 'signin.html', {
                'signin': AuthenticationForm,
                'error': 'Authentication error',
            })


@login_required
def signOut(request):
    try:
        logout(request)
        return redirect('home')
    except Exception as _:
        return redirect('home')


@login_required
def create_task(request):
    if request.method == 'GET':
        return render(request, 'create_task.html', {
            'form': TaskForm,
        })
    else:
        try:
            form = TaskForm(request.POST)
            
            if not form.is_valid():
                logger.warning(
                    f"Intento de crear tarea con datos inválidos por usuario: {request.user.username} "
                    f"desde IP: {request.META.get('REMOTE_ADDR')}. Errores: {form.errors}"
                )
                return render(request, 'create_task.html', {
                    'form': form,
                    'error': 'Please enter valid data',
                })
            
            # Guardar sin commit para agregar el usuario antes de persistir
            object_task = form.save(commit=False)
            object_task.user = request.user  # Asignar el usuario autenticado
            object_task.save()  # Guardar en la base de datos 
            
            # Registrar la creación exitosa de la tarea
            logger.info(
                f"Tarea creada exitosamente por usuario: {request.user.username} "
                f"(ID tarea: {object_task.id}) desde IP: {request.META.get('REMOTE_ADDR')}"
            )
            return redirect('tasks')
        
        except ValueError as e:
            logger.error(
                f"Error de validación al crear tarea para usuario: {request.user.username}. "
                f"Detalles: {str(e)}",
                exc_info=True
            )
            return render(request, 'create_task.html', {
                'form': TaskForm,
                'error': 'Please enter valid data',
            })
        
        except IntegrityError as e:
            logger.error(
                f"Error de integridad de datos al crear tarea para usuario: {request.user.username}",
                exc_info=True
            )
            return render(request, 'create_task.html', {
                'form': TaskForm,
                'error': 'Error saving task. Please try again.',
            })
        
        except Exception as e:
            logger.error(
                f"Error inesperado al crear tarea para usuario: {request.user.username}",
                exc_info=True
            )
            return render(request, 'create_task.html', {
                'form': TaskForm,
                'error': 'Error creating task. Please try again later.',
            })


@login_required
def tasks(request):
    try:
        tasks = Task.objects.filter(
            user=request.user,
            dateCompleted__isnull=True
        ).order_by('-important', '-created')
        
        logger.info(
            f"Usuario: {request.user.username} accedió a tareas "
            f"(Total: {tasks.count()}) desde IP: {request.META.get('REMOTE_ADDR')}"
        )
        
        return render(request, 'tasks.html', {
            'tasks': tasks,
        })
    
    except Exception as e:
        logger.error(
            f"Error al recuperar tareas para usuario: {request.user.username}",
            exc_info=True
        )
        return render(request, 'tasks.html', {
            'tasks': [],
            'error': 'Error loading tasks. Please try again later.',
        })


@login_required
def task_detail(request, task_id):
    try:
        task = get_object_or_404(Task, id=task_id, user=request.user)
        
        if request.method == 'GET':
            form = TaskForm(instance=task)
            logger.info(
                f"Usuario: {request.user.username} accedió a detalle de tarea ID: {task_id} "
                f"desde IP: {request.META.get('REMOTE_ADDR')}"
            )
            return render(request, 'task_detail.html', {
                'task': task,
                'form': form,
            })
        else:
            form = TaskForm(request.POST, instance=task)
            
            if not form.is_valid():
                logger.warning(
                    f"Intento de actualizar tarea ID: {task_id} con datos inválidos "
                    f"por usuario: {request.user.username}. Errores: {form.errors}"
                )
                return render(request, 'task_detail.html', {
                    'task': task,
                    'form': form,
                    'error': 'Please enter valid data',
                })
            
            form.save()
            logger.info(
                f"Tarea ID: {task_id} actualizada por usuario: {request.user.username} "
                f"desde IP: {request.META.get('REMOTE_ADDR')}"
            )
            return redirect('tasks')
    
    except ValueError as e:
        logger.error(
            f"Error de validación al actualizar tarea ID: {task_id} "
            f"para usuario: {request.user.username}. Detalles: {str(e)}",
            exc_info=True
        )
        form = TaskForm(instance=task)
        return render(request, 'task_detail.html', {
            'task': task,
            'form': form,
            'error': 'Please enter valid data',
        })
    
    except OperationalError as e:
        logger.error(
            f"Error operacional de base de datos al actualizar tarea ID: {task_id}",
            exc_info=True
        )
        form = TaskForm(instance=task)
        return render(request, 'task_detail.html', {
            'task': task,
            'form': form,
            'error': 'The database is locked. Please try again later.',
        })
    
    except IntegrityError as e:
        logger.error(
            f"Error de integridad de datos al actualizar tarea ID: {task_id}",
            exc_info=True
        )
        form = TaskForm(instance=task)
        return render(request, 'task_detail.html', {
            'task': task,
            'form': form,
            'error': 'Error saving task. Please try again.',
        })
    
    except Exception as e:
        # CAMBIO 8: Manejar excepciones inesperadas
        logger.error(
            f"Error inesperado al procesar tarea ID: {task_id} "
            f"para usuario: {request.user.username}",
            exc_info=True
        )
        form = TaskForm(instance=task)
        return render(request, 'task_detail.html', {
            'task': task,
            'form': form,
            'error': 'Error processing task. Please try again later.',
        })


@login_required
def task_complete(request, task_id):
    # Validación: Verificar que task_id sea un número válido
    if not task_id or not str(task_id).isdigit():
        return redirect('tasks')
    
    if request.method == 'POST':
        try:
            task = get_object_or_404(Task, id=task_id, user=request.user)
            task.dateCompleted = timezone.now()
            task.save()
            return redirect('tasks')
        except Exception as e:
            return redirect('tasks')
    else:
        return redirect('tasks')


@login_required
def delete_task(request, task_id):
    # Validación: Verificar que task_id sea un número válido
    if not task_id or not str(task_id).isdigit():
        return redirect('tasks')
    
    if request.method == 'POST':
        try:
            task = get_object_or_404(Task, id=task_id, user=request.user)
            task.delete()
            return redirect('tasks')
        except Exception as e:
            return redirect('tasks')
    else:
        return redirect('tasks')


@login_required
def tasks_completed(request):
    """Listar todas las tareas completadas"""
    try:
        # ordenamiento
        tasks = Task.objects.filter(
            user=request.user, 
            dateCompleted__isnull=False
        ).order_by('-dateCompleted')
        
        return render(request, 'tasks_completed.html', {
            'tasks': tasks,
        })
    except Exception:
        # En caso de error, retornar lista vacía
        return render(request, 'tasks_completed.html', {
            'tasks': [],
        })
