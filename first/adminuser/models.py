from django.core.validators import MinValueValidator
from django.db import models, transaction
from django.db.models import Sum
from user.models import CustomUser


class Category(models.Model):
    name = models.CharField(max_length=100, verbose_name='Наименование')
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='categories')

    def __str__(self):
        return f'{self.name}'

    class Meta:
        verbose_name = 'Категория'
        verbose_name_plural = 'Категории'
        unique_together = ['name', 'user']


class Type(models.Model):
    name = models.CharField(max_length=50, verbose_name='Тип', )
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='types')

    def __str__(self):
        return f"{self.name}"

    class Meta:
        verbose_name = 'Тип'
        verbose_name_plural = 'Типы'
        unique_together = ['name', 'user']


class Products(models.Model):
    name = models.CharField(max_length=150, verbose_name='Наименования')
    description = models.TextField(null=True, blank=True, verbose_name='Описание товара')
    price = models.DecimalField(max_digits=10, decimal_places=2, verbose_name='Цена', blank=True, null=True,
                                validators=[MinValueValidator(0)], default=0.00)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, blank=True, null=True, verbose_name='Категория')
    type = models.ForeignKey('Type', on_delete=models.PROTECT, verbose_name='Тип')
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.name} {self.description} {self.price} {self.category} {self.type} {self.user}"

    def display_price(self):
        return f"{self.price} ₽" if self.price else "Цена не указана"

    def is_available(self):
        return self.price is not None and self.price > 0

    def get_display_price(self):
        return f"{self.price} ₽" if self.price else "Цена не указана"

    class Meta:
        indexes = [
            models.Index(fields=['user', 'name']),
            models.Index(fields=['category']),
            models.Index(fields=['type']),
        ]
        verbose_name = "Товар"
        verbose_name_plural = 'Товары'
        unique_together = ['name', 'user']


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

    def get_status_display(self):
        return dict(self.STATUS_CHOICES).get(self.status, self.status)

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

class DisbursementCashOrder(models.Model):
    number_order = models.CharField(max_length=50, unique=True, verbose_name="Номер ордера")
    date = models.DateTimeField(auto_created=True, verbose_name='Дата')
    sum_amount = models.DecimalField(max_digits=10, decimal_places=2, verbose_name='Сумма', editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)


    def __str__(self):
        return f"Номер Ордера {self.number_order}: Дата - {self.date}: Сумма - {self.sum_}: Пользователь {self.user}"


    def save(self, *args, **kwargs):
        pass


    class Meta:
        verbose_name = "Расходы кассовый ордер"
        verbose_name_plural = "Расходные кассовые ордера"
