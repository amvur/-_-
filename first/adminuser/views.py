from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import (
    Category, Type, Products, Order, OrderItem, PaymentOrder, CashReceiptOrder,
)
from .serializers import (
    CategorySerializers, TypeSerializers,  ProductSerializers
)
from django.contrib.auth import get_user_model

User = get_user_model()



class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializers
    permission_classes =[permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields=['name']

    def get_queryset(self):
        return self.queryset.filter(user=self.queryset.user)

    def perform_create(self, serializer):
        serializer.save(user=self.queryset.user)



class TypeviewSet(viewsets.ModelViewSet):
    queryset = Type.objects.all()
    serializer_class = TypeSerializers
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_field = ['name']


    def get_queryset(self):
        return self.queryset.filter(user=self.queryset.user)

    def perform_create(self, serializer):
        serializer.save(user=self.queryset.user)



class ProductsViewSet(viewsets.ModelViewSet):
    queryset = Products.objects.all()
    serializer_class = ProductSerializers
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_field = ['name']


    def get_queryset(self):
        return self.queryset.filter(user=self.queryset.user)

    def perform_create(self, serializer):
        serializer.save(user=self.queryset.user)


