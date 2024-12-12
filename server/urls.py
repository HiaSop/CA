from . import views
from django.contrib.auth import views as auth_views
from django.urls import path

urlpatterns = [
    path('login/', views.user_login, name='login'),
    path('register/', views.user_register, name='register'),
    path('upload-csr/', views.upload_csr, name='upload_csr'),
]
