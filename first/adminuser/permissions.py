from rest_framework.permissions import BasePermission

class IsCreatorOrReadOnly(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        return obj.created_by == request.user

class IsApprover(BasePermission):
    def has_permission(self, request, view):
        return request.user.groups.filter(name='Approvers').exists()

class IsCashier(BasePermission):
    def has_permission(self, request, view):
        return request.user.groups.filter(name='Cashiers').exists()