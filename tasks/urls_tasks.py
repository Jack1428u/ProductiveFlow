from django.urls import path
from . import views

urlpatterns = [
    path('',views.home,name='home'),
    path('signup/',views.signUp,name='signup'),
    path('tasks/',views.tasks,name='tasks'),
    path('logout/',views.signOut,name='logout'),
    path('signin/',views.signIn,name='signin'),
    path('tasks/create',views.create_task,name='create_task'),
    path('tasks/<int:task_id>/',views.task_detail,name='task_detail'),
    path('tasks/<int:task_id>/complete/',views.task_complete,name='complete_task'),
    path('task/<int:task_id>/delete/',views.delete_task,name='delete_task'),
    path('tasks_completed/',views.tasks_completed,name='tasks_completed')
]
#    path('tasks/<int:task_id>/',views.task_detail,name='task_detail'),