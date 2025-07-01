from django.urls import path, include
from .views import CustomAuthToken, RegisterView, LogoutView
from rest_framework.routers import DefaultRouter

router = DefaultRouter()


urlpatterns =[
    path('api/', include(router.urls)),
    path('api/login/', CustomAuthToken.as_view(), name='login'),  # Для получения токена
    path('api/logout/', LogoutView.as_view(), name='logout'),  # Если нужен logout
    path('api/register/', RegisterView.as_view(), name='register'),
]