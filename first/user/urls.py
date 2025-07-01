from django.urls import path, include
from .views import CustomAuthToken, RegisterView
from rest_framework.routers import DefaultRouter
urlpatterns =[
    path('login/', CustomAuthToken.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('au/', include('adminuser.urls'))
]