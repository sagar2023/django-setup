from django.db.models import Q
from rest_framework.permissions import BasePermission
from accounts.models import User


class CheckSuperAdminRolePermission(BasePermission):
    """
        CheckSuperAdminRolePermission class used to check user role is super-admin user or not.
    """
    message = "Permission is allowed only to super-admin user."

    # def has_permission(self, request, view):
    #     if User.objects.filter(id=request.user.id, role=User.RoleType.SUPER_ADMIN_USER).exists():
    #         return True
    #     return False

    def has_permission(self, request, view):
        try:
            if request.user.role == User.RoleType.SUPER_ADMIN_USER:
                return True
        except Exception:
            pass
        return False


class CheckUserRolePermission(BasePermission):
    """
        CheckUserRolePermission class used to check user role is normal user or not.
    """
    message = "Permission is allowed only to normal user."

    def has_permission(self, request, view):
        try:
            if request.user.role == User.RoleType.NORMAL_USER:
                return True
        except Exception:
            pass
        return False


class CheckAdminAndSuperAdminRolePermission(BasePermission):
    """
        CheckAdminAndSuperAdminRolePermission class used to check user role is Admin or Super-Admin user.
    """
    message = "Permission is allowed only to admin or super-admin user."

    def has_permission(self, request, view):
        try:
            if request.user.role in (User.RoleType.ADMIN_USER, User.RoleType.SUPER_ADMIN_USER):
                return True
        except Exception:
            pass
        return False


class CheckAdminAndUserRolePermission(BasePermission):
    """
        CheckAdminAndUserRolePermission class used to check user role is Admin or Normal user.
    """
    message = "Permission is allowed only to admin or normal user."

    def has_permission(self, request, view):
        try:
            if request.user.role in (User.RoleType.NORMAL_USER, User.RoleType.ADMIN_USER):
                return True
        except Exception:
            pass
        return False


class CheckAdminRolePermission(BasePermission):
    """
        CheckAdminRolePermission class used to check user role is Admin or not.
    """
    message = "Permission is allowed only to admin user."

    def has_permission(self, request, view):
        try:
            if request.user.role == User.RoleType.ADMIN_USER:
                return True
        except Exception:
            pass
        return False
