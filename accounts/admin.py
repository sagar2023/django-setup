from django.contrib import admin
from accounts.models import User, UserPermission

# Register your models here.


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'first_name', 'last_name', 'role', 'is_active', 'is_deleted',
                    'is_superuser', 'created_at',)


@admin.register(UserPermission)
class UserPermissionAdmin(admin.ModelAdmin):
    list_display = ('id', 'user_id', 'business_group', 'category', 'business_unit', 'country',)
