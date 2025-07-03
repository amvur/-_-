from django.contrib import admin
from .models import CashExpenseOrder, ExpenseOrderAttachment

@admin.register(CashExpenseOrder)
class CashExpenseOrderAdmin(admin.ModelAdmin):
    list_display = ('number', 'expense_date', 'recipient', 'amount', 'status')
    list_filter = ('status', 'expense_date')
    search_fields = ('number', 'recipient', 'basis')
    readonly_fields = ('number', 'created_at', 'updated_at', 'created_by', 'approved_by')

@admin.register(ExpenseOrderAttachment)
class ExpenseOrderAttachmentAdmin(admin.ModelAdmin):
    list_display = ('order', 'description', 'uploaded_at')
    search_fields = ('order__number', 'description')