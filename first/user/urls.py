from django.urls import path, include
from rest_framework import routers
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import *


urlpatterns = [
    path('api/auth/login', LoginView.as_view()),
    path('api/auth/me', GetUserView.as_view()),
    path('api/auth/register', RegisterView.as_view(), name='register'),
    path('api/auth/token-refresh/', TokenRefreshView.as_view()),
    path('api/auth/refresh', RefreshView.as_view()),
    path('api/auth/logout', LogoutView.as_view()),
]
