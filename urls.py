"""user_auth URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from user_auth.user_auth import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('signup/', views.SignupView.as_view(), name='signup'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('password-reset/', views.PasswordResetEmailView.as_view(), name='password-reset'),
    path('profile/', views.ProfileView.as_view(), name='profile'),
    path('user-list/', views.UserListView.as_view(), name='user-list'),
    path('logout/', views.LogoutView.as_view(), name='log-out'),

]
