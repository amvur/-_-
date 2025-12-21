from zoneinfo import available_timezones

from rest_framework.response import Response
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q, Sum
from .models import Category, Type, Products, Order, OrderItem, PaymentOrder, CashReceiptOrder, DisbursementCashOrder
from .serializers import (
    CategorySerializer, TypeSerializer, ProductsSerializer,
    OrderSerializer, OrderItemSerializer,
    PaymentOrderSerializer, CashReceiptOrderSerializer,
    CategoryListSerializer, TypeListSerializer, ProductsListSerializer, OrderListSerializer, DisbursementCashOrderSerializer
)


class UserObjectsOnlyPermission(permissions.BasePermission):
    """Разрешить только на свои объекты"""

    def has_object_permission(self, request, view, obj):
        return obj.user == request.user


class UserObjectsOnlyViewSetMixin:
    """Миксин для фильтрации только своих объектов"""

    def get_queryset(self):
        return super().get_queryset().filter(user=self.request.user)


class CategoryViewSet(UserObjectsOnlyViewSetMixin, viewsets.ModelViewSet):
    queryset = Category.objects.all()
    permission_classes = [permissions.IsAuthenticated, UserObjectsOnlyPermission]

    def get_serializer_class(self):
        if self.action == 'list':
            return CategoryListSerializer
        return CategorySerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class TypeViewSet(UserObjectsOnlyViewSetMixin, viewsets.ModelViewSet):
    queryset = Type.objects.all()
    permission_classes = [permissions.IsAuthenticated, UserObjectsOnlyPermission]

    def get_serializer_class(self):
        if self.action == 'list':
            return TypeListSerializer
        return TypeSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class ProductsViewSet(UserObjectsOnlyViewSetMixin, viewsets.ModelViewSet):
    queryset = Products.objects.all()
    permission_classes = [permissions.IsAuthenticated, UserObjectsOnlyPermission]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['category', 'type']

    def get_serializer_class(self):
        if self.action == 'list':
            return ProductsListSerializer
        return ProductsSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class OrderViewSet(UserObjectsOnlyViewSetMixin, viewsets.ModelViewSet):
    queryset = Order.objects.all()
    permission_classes = [permissions.IsAuthenticated, UserObjectsOnlyPermission]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['status', 'date']

    def get_serializer_class(self):
        if self.action == 'list':
            return OrderListSerializer
        return OrderSerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['POST'])
    def change_status(self, request, pk=None):
        order = self.get_object()
        new_status = request.data.get('status')

        if new_status not in dict(Order.STATUS_CHOICES):
            return Response(
                {'Error': 'Неверный статус '},
                status=status.HTTP_400_BAD_REQUEST
            )
        order.status = new_status
        order.save()
        return Response({'status': 'Cтатус обновлен', 'new_status': order.status})


class OrderItemViewSet(UserObjectsOnlyViewSetMixin, viewsets.ModelViewSet):
    queryset = OrderItem.objects.all()
    serializer_class = OrderItemSerializer
    permission_classes = [permissions.IsAuthenticated, UserObjectsOnlyPermission]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class CashReceiptOrderViewSet(UserObjectsOnlyViewSetMixin, viewsets.ModelViewSet):
    queryset = CashReceiptOrder.objects.all()
    serializer_class = CashReceiptOrderSerializer
    permission_classes = [permissions.IsAuthenticated, UserObjectsOnlyPermission]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class DisbursementCashOrderViewSet(UserObjectsOnlyViewSetMixin, viewsets.ModelViewSet):
    queryset = DisbursementCashOrder.objects.all()
    serializer_class = DisbursementCashOrderSerializer
    permission_classes = [permissions.IsAuthenticated, UserObjectsOnlyPermission]
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class PaymentOrderViewSet(UserObjectsOnlyViewSetMixin, viewsets.ModelViewSet):
    queryset = PaymentOrder.objects.all()
    serializer_class = PaymentOrderSerializer
    permission_classes = [permissions.IsAuthenticated, UserObjectsOnlyPermission]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class DashboardViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        user = request.user

        orders_count = Order.objects.filter(user=user).count()
        total_revenue = Order.objects.filter(
            user=user,
            status__in=['cash', 'without_cash']
        ).aggregate(total=Sum('total_sum'))['total'] or 0

        products_count = Products.objects.filter(user=user).count()
        available_products = Products.objects.filter(user=user, is_available=True).count()

        return Response(
            {
                'orders_count': orders_count,
                'total_revenue': float(total_revenue),
                'products_count': products_count,
                'available_products': available_products
            }
        )
# test commit

