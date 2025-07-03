from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    CategoryViewSet,
    TypeviewSet,
    ProductsViewSet,
    OrderViewSet,
    CashExpenseOrderViewSet,
    ExpenseOrderAttachmentViewSet
)

router = DefaultRouter()

# Регистрация ViewSets
router.register(r'categories', CategoryViewSet, basename='category')
router.register(r'types', TypeviewSet, basename='type')
router.register(r'products', ProductsViewSet, basename='product')
router.register(r'orders', OrderViewSet, basename='order')
router.register(r'expense-orders', CashExpenseOrderViewSet, basename='expense-order')
router.register(
    r'expense-orders/(?P<order_pk>\d+)/attachments',
    ExpenseOrderAttachmentViewSet,
    basename='expense-order-attachment'
)

urlpatterns = [
    path('', include(router.urls)),
]