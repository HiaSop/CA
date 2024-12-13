from . import views
from django.contrib.auth import views as auth_views
from django.urls import path

urlpatterns = [
    path('login/', views.user_login, name='login'),
    path('homepage/',views.homepage,name='homepage'),
    path('register/', views.user_register, name='register'),
    path('upload-csr/', views.upload_csr, name='upload_csr'),
    path('api/sign_csr', views.sign_csr, name='sign_csr'),
    path('view_certificates', views.view_certificates, name='view_certificates'),
    path('api/verify_certificate', views.verify_certificate, name='verify_certificate'),
    path('generate_csr/', views.generate_csr, name='generate_csr'),
]
