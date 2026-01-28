from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'categories', views.CategoryViewSet)
router.register(r'types', views.TypeViewSet)
router.register(r'product', views.ProductsViewSet)
router.register(r'orders', views.OrderViewSet)
router.register(r'order-items', views.OrderItemViewSet)
router.register(r'cash-receipts', views.CashReceiptOrderViewSet)
router.register(r'payment-orders', views.PaymentOrderViewSet)
router.register(r'dashboard', views.DashboardViewSet, basename='dashboard')
router.register(r'rco', views.DisbursementCashOrderViewSet)

urlpatterns = [
    path('api/', include(router.urls)),
    path('api/auth/', include('rest_framework.urls', namespace='rest_framework_auth')),
]

