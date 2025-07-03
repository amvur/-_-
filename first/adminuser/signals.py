from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.utils import timezone
from .models import CashExpenseOrder


@receiver(pre_save, sender=CashExpenseOrder)
def generate_order_number(sender, instance, **kwargs):
    if not instance.number:
        year = timezone.now().strftime('%Y')
        last_order = CashExpenseOrder.objects.filter(
            number__startswith=f'RKO-{year}-'
        ).order_by('-number').first()

        if last_order:
            last_num = int(last_order.number.split('-')[-1])
            new_num = last_num + 1
        else:
            new_num = 1

        instance.number = f'RKO-{year}-{str(new_num).zfill(5)}'