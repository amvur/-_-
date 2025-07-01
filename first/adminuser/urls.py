from django.urls import path, include
from .views import *
from rest_framework.routers import DefaultRouter

router =DefaultRouter()

router.register('order', OrderViewSet)

urlpatterns =[
    path('api', include(router.urls)),
]