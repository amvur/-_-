from django.db import models, transaction
from django.db.models import Sum
from user.models import CustomUser

from django.contrib.auth import get_user_model
from django.core.validators import MinValueValidator




class Category(models.Model):
    name = models.CharField(max_length=100, verbose_name='Наименование')
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='categories')

    def __str__(self):
        return f'{self.name}'

    class Meta:
        verbose_name = 'Категория'
        verbose_name_plural = 'Категории'


class Type(models.Model):
    name = models.CharField(max_length=50, verbose_name='Тип', )
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='types')

    def __str__(self):
        return f"{self.types}"

    class Meta:
        verbose_name = 'Тип'
        verbose_name_plural = 'Типы'


class Products(models.Model):
    name = models.CharField(max_length=150, verbose_name='Наименования')
    description = models.TextField(null=True, blank=True, verbose_name='Описание товара')
    price = models.DecimalField(max_digits=10, decimal_places=2, verbose_name='Цена', blank=True, null=True)
    category = models.ForeignKey("Category", on_delete=models.CASCADE, blank=True, null=True, verbose_name='Категория')
    type = models.ForeignKey('Type', on_delete=models.PROTECT, verbose_name='Тип')
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.name} {self.description} {self.price} {self.category} {self.type} {self.user}"

    class Meta:
        verbose_name = "Товар"
        verbose_name_plural = 'Товары'


class Order(models.Model):
    STATUS_CHOICES = [
        ('unpaid', 'Не оплачен'),
        ('cash', 'Наличными'),
        ('without_cash', 'Без налич'),
        ('canceled', 'Отменено'),
    ]
    number = models.CharField('Номер ордера', max_length=50, unique=True)
    date = models.DateTimeField(auto_now_add=True, verbose_name='Дата и время')
    status = models.CharField(
        max_length=15,
        choices=STATUS_CHOICES,
        default='unpaid',
        verbose_name='Статус'
    )
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

    def __str__(self):
        return f'Заказ {self.id} на столе {self.table}'

    def total_sum(self):
        return self.orderitem_set.aggregate(total=Sum('sum'))['total'] or 0

    def products_list(self):
        return ", ".join([item.product.name for item in self.orderitem_set.all()])

    def save(self, *args, **kwargs):
        # Получаем предыдущий статус, если заказ уже существует
        if self.pk:
            old_status = Order.objects.get(pk=self.pk).status
        else:
            old_status = None

        if not self.number:
            last_number = Order.objects.filter(
                user=self.user
            ).order_by('-id').values_list('number', flat=True).first()
            if last_number:

                try:
                    last_num = int(last_number.split('/')[-1])
                except (IndexError, ValueError):
                    last_num = 0
            else:
                last_num = 0

            self.number = f'Order/{self.date.strftime("%Y%m%d")}/{last_num + 1}'
        super().save(*args, **kwargs)

        # Обрабатываем изменение статуса
        if old_status != self.status:
            self.handle_status_change(old_status)

    def handle_status_change(self, old_status):
        with transaction.atomic():
            if self.status == 'cash' and self.orderitem_set.exists():
                self.cashreceiptorder_order.all().delete()
                CashReceiptOrder.objects.create(
                    order=self,
                    sum=self.total_sum()
                )
            elif self.status == 'without_cash' and self.orderitem_set.exists():
                self.paymentorder_order.all().delete()

                PaymentOrder.objects.create(
                    order=self,
                    sum=self.total_sum()
                )
            elif old_status == 'cash':
                self.cashreceiptorder_order.all().delete()

            elif old_status == 'without_cash':
                self.paymentorder_order.all().delete()

    class Meta:
        verbose_name = 'Стол заказов'
        verbose_name_plural = 'Столы заказов'


class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, verbose_name='Заказ')
    product = models.ForeignKey(Products, on_delete=models.PROTECT, verbose_name='Товар')
    count = models.IntegerField(verbose_name='Количество')
    price = models.DecimalField(max_digits=10, decimal_places=2, verbose_name='Цена', editable=False)
    sum = models.DecimalField(max_digits=10, decimal_places=2, editable=False, verbose_name='Сумма')
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

    def __str__(self):
        return f'{self.product.name} в заказе {self.order.id}'

    def save(self, *args, **kwargs):
        self.price = self.product.price
        self.sum = self.price * self.count
        super().save(*args, **kwargs)

    class Meta:
        verbose_name = 'Элемент заказа'
        verbose_name_plural = 'Элементы заказа'


class CashReceiptOrder(models.Model):
    number = models.CharField('Номер ордера', max_length=50, unique=True)
    date = models.DateTimeField(auto_now_add=True, verbose_name="Дата")
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='cashreceiptorder_order',
                              verbose_name='Заказ', editable=False)
    sum = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="Сумма", editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.date}, {self.order}, {self.sum}"

    def save(self, *args, **kwargs):
        # Проверяем что заказ оплачен и есть товары
        if self.order.status != 'cash':
            raise ValueError("Кассовый ордер можно создать только для оплаченного заказа")

        if not self.order.orderitem_set.exists():
            raise ValueError("Нельзя создать кассовый ордер для заказа без товаров")

        # Автоматически считаем сумму
        self.sum = self.order.total_sum()

        # Проверяем что сумма положительная
        if self.sum <= 0:
            raise ValueError("Сумма кассового ордера должна быть больше 0")
        if not self.number:
            last_number = CashReceiptOrder.objects.filter(
                user=self.user
            ).order_by('-id').values_list('number', flat=True).first()
            if last_number:

                try:
                    last_num = int(last_number.split('/')[-1])
                except (IndexError, ValueError):
                    last_num = 0
            else:
                last_num = 0

            self.number = f'ПКО/{self.date.strftime("%Y%m%d")}/{last_num + 1}'
        super().save(*args, **kwargs)

    class Meta:
        verbose_name = "Приходный кассовый ордер"
        verbose_name_plural = "Приходные кассовые ордера"


# Create your models here.
class PaymentOrder(models.Model):
    number = models.CharField('Номер ордера', max_length=50, unique=True)
    date = models.DateTimeField(auto_now_add=True, verbose_name='Дата')
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='paymentorder_order',
                              verbose_name='Заказ', editable=False)
    sum = models.DecimalField(max_digits=10, decimal_places=2, verbose_name='Сумма', editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

    def __str__(self):
        return f"Дата:{self.date} стол заказа{self.order} Сумма{self.sum}"

    def save(self, *args, **kwargs):
        # Проверяем что заказ оплачен и есть товары
        if self.order.status != 'without_cash':
            raise ValueError("Платежное поручение можно создать только для оплаченного заказа")

        if not self.order.orderitem_set.exists():
            raise ValueError("Нельзя создать платежное поручение для заказа без товаров")

        # Автоматически считаем сумму
        self.sum = self.order.total_sum()

        # Проверяем что сумма положительная
        if self.sum <= 0:
            raise ValueError("Сумма платежное поручение должна быть больше 0")
        if not self.number:
            last_number = PaymentOrder.objects.filter(
                user=self.user
            ).order_by('-id').values_list('number', flat=True).first()
            if last_number:

                try:
                    last_num = int(last_number.split('/')[-1])
                except (IndexError, ValueError):
                    last_num = 0
            else:
                last_num = 0

            self.number = f'ПП/{self.date.strftime("%Y%m%d")}/{last_num + 1}'

        super().save(*args, **kwargs)

    class Meta:
        verbose_name = "Платежное поручение"
        verbose_name_plural = "Платежные поручении"




User = get_user_model()

class CashExpenseOrder(models.Model):
    """Модель расходного кассового ордера"""
    class Status(models.TextChoices):
        DRAFT = 'draft', 'Черновик'
        PENDING = 'pending', 'На согласовании'
        APPROVED = 'approved', 'Утвержден'
        REJECTED = 'rejected', 'Отклонен'
        PAID = 'paid', 'Оплачен'

    number = models.CharField('Номер', max_length=50, unique=True)
    created_at = models.DateTimeField('Дата создания', auto_now_add=True)
    updated_at = models.DateTimeField('Дата обновления', auto_now=True)
    expense_date = models.DateField('Дата расхода')
    amount = models.DecimalField(
        'Сумма',
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(0.01)]
    )
    currency = models.CharField('Валюта', max_length=3, default='RUB')
    recipient = models.CharField('Получатель', max_length=255)
    basis = models.TextField('Основание')
    comment = models.TextField('Комментарий', blank=True)
    status = models.CharField(
        'Статус',
        max_length=20,
        choices=Status.choices,
        default=Status.DRAFT
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='created_expense_orders',
        verbose_name='Создатель'
    )
    approved_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='approved_expense_orders',
        verbose_name='Утвердил',
        null=True,
        blank=True
    )
    cashier = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='cashier_expense_orders',
        verbose_name='Кассир',
        null=True,
        blank=True
    )

    class Meta:
        verbose_name = 'Расходный кассовый ордер'
        verbose_name_plural = 'Расходные кассовые ордера'
        ordering = ['-expense_date', '-created_at']

    def __str__(self):
        return f'РКО №{self.number} от {self.expense_date}'

class ExpenseOrderAttachment(models.Model):
    """Прикрепленные документы к РКО"""
    order = models.ForeignKey(
        CashExpenseOrder,
        on_delete=models.CASCADE,
        related_name='attachments'
    )
    file = models.FileField('Файл', upload_to='expense_orders/attachments/')
    description = models.CharField('Описание', max_length=255, blank=True)
    uploaded_at = models.DateTimeField('Дата загрузки', auto_now_add=True)

    class Meta:
        verbose_name = 'Приложение к РКО'
        verbose_name_plural = 'Приложения к РКО'

    def __str__(self):
        return f'Приложение к РКО №{self.order.number}'