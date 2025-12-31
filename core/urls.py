from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    path('', views.home, name='home'),
    path('home/', views.home, name='home_public'),  # Alias for templates
    path('about/', views.about, name='about'),
    path('teachers/', views.teachers, name='teachers'),
    path('courses/', views.course_list, name='course_list'),
    path('courses/detail/', views.course_detail, name='course_detail'),
    path('teachers/profile/', views.teacher_profile, name='teacher_profile'),
]
