from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import viewsets, mixins, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import CashExpenseOrder, ExpenseOrderAttachment
from .serializers import (
    CashExpenseOrderSerializer,
    CashExpenseOrderCreateSerializer,
    CashExpenseOrderUpdateSerializer,
    CashExpenseOrderStatusSerializer,
    ExpenseOrderAttachmentSerializer
)
from .permissions import (
    IsCreatorOrReadOnly,
    IsApprover,
    IsCashier
)

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



class CashExpenseOrderViewSet(viewsets.ModelViewSet):
    queryset = CashExpenseOrder.objects.all()
    permission_classes = [IsAuthenticated, IsCreatorOrReadOnly]

    def get_serializer_class(self):
        if self.action == 'create':
            return CashExpenseOrderCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return CashExpenseOrderUpdateSerializer
        return CashExpenseOrderSerializer

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated, IsApprover])
    def approve(self, request, pk=None):
        order = self.get_object()
        serializer = CashExpenseOrderStatusSerializer(
            order,
            data={'status': 'approved'},
            partial=True
        )
        if serializer.is_valid():
            serializer.save(approved_by=request.user)
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated, IsApprover])
    def reject(self, request, pk=None):
        order = self.get_object()
        serializer = CashExpenseOrderStatusSerializer(
            order,
            data={'status': 'rejected'},
            partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated, IsCashier])
    def mark_as_paid(self, request, pk=None):
        order = self.get_object()
        serializer = CashExpenseOrderStatusSerializer(
            order,
            data={'status': 'paid'},
            partial=True
        )
        if serializer.is_valid():
            serializer.save(cashier=request.user)
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ExpenseOrderAttachmentViewSet(
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet
):
    serializer_class = ExpenseOrderAttachmentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ExpenseOrderAttachment.objects.filter(
            order_id=self.kwargs['order_pk']
        )

    def perform_create(self, serializer):
        order = CashExpenseOrder.objects.get(pk=self.kwargs['order_pk'])
        serializer.save(order=order)