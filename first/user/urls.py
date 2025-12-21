from django.urls import path, include
from rest_framework import routers
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import *

router = routers.DefaultRouter()
# router.register(r'users', UserViewSet, basename='user')

urlpatterns = [
    # path('api/', include(router.urls)),

    path('api/auth/login', LoginView.as_view()),
    path('api/auth/me', GetUserView.as_view()),
    path('api/auth/register', RegisterView.as_view()),
    path('api/auth/refresh', RefreshView.as_view()),
    path('api/auth/logout', LogoutView.as_view()),
]
