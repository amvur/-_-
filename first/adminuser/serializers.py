from django.template.context_processors import request
from rest_framework import serializers
from .models import CashReceiptOrder, Category, Products, Type, Order, OrderItem, PaymentOrder


class TypeSerializers(serializers.ModelSerializer):
    class Meta:
        model = Type
        fields = ["name"]
        read_only_fields = ["user"]

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class CategorySerializers(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['name']
        read_only_fields = ['user']

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class ProductSerializers(serializers.ModelSerializer):
    class Meta:
        model = Products
        fields = [
            "name", "description", "price", "category", "type"
        ]
        read_only_fields = ["user"]

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class OrderItemSetSerializers(serializers.ModelSerializer):
    product = ProductSerializers(read_only=True)
    product_id = serializers.PrimaryKeyRelatedField(
        queryset=Products.objects.all(),
        source='product',
        write_only=True,
        required=True
    )

    class Meta:
        model = OrderItem
        fields = ['id', 'product', 'product_id', 'count', 'price', 'sum']
        read_only_fields = ['price', 'sum']



class OrderSerializers(serializers.ModelSerializer):
    item = OrderItemSetSerializers(source='orderItem_set', many=True, required=False)
    total_sum = serializers.DecimalField(
        max_digits=10,
        decimal_places=2,
        read_only=True
    )
    status_display = serializers.CharField(
        source='get_status_display',
        read_only=True
    )

    class Meta:
        model = Order
        fields = [
            'id', 'number', 'date', 'status', 'status_display',
            'user', 'items', 'total_sum'
        ]


    def create(self, validated_data):
        items_data = validated_data.pop('orderitem_set', [])
        order = Order.objects.create(**validated_data, user=self.context['request'].user)

        for item_data in items_data:
            OrderItem.objects.create(
                order=order,
                prduct = item_data['product'],
                cout = item_data['count'],
                user = self.context['request'].user
            )
        return order

    def update(self, instance, validated_data):
        items_data = validated_data.pop('orderitem_set', None)


        instance.status = validated_data.get('status', instance.status)
        instance.save()

        if items_data in None:
            current_items = {item.id: item for item in instance.orderitem_set.all()}
            for item_data in items_data:
                item_id = item_data.get('id', None)
                if item_id == current_items:
                    item = current_items[item_id]
                    item.product = item_data['product']
                    item.count = item_data['count']
                    item.save()

                else:
                    OrderItem.objects.create(
                        order=instance,
                        product=item_data['product'],
                        count=item_data['count'],
                        user=self.context['request'].user
                    )
            kept_ids = [i.get('id') for i in items_data if i.get('id')]
            for item_id, item in current_items.items():
                if item_id not in kept_ids:
                    item.delete()

        return instance



