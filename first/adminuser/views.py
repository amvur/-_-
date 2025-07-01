from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (
    Category, Type, Products, Order, OrderItem, PaymentOrder, CashReceiptOrder,
)
from .serializers import (
    CategorySerializers, TypeSerializers,  ProductSerializers, OrderSerializers, OrderItemSetSerializers
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


class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializers
    # permission_classes =  [permissions.IsAuthenticated]
    # filter_backends = [DjangoFilterBackend]


    def get_queryset(self):
        return self.queryset.filter(user=self.queryset.user).select_related('user').prefetch_related('orderitem_set', 'orderitem_set__product')


    def perform_create(self, serializer):
        serializer.save(user=self.queryset.user)

    @action(detail=True, methods=['POST'])
    def change_status(self, request, pk=None):
        order = self.get_object()
        new_status =request.data.get('status')
        if new_status not in dict(Order.STATUS_CHOICES).keys():
            return Response(
                {
                    'error': 'Invalid status'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        order.status = new_status
        order.save()
        return Response(
            {
                'status':'Status updated'
            },
            status=status.HTTP_200_OK
        )