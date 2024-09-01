from django.urls import path
from admins import views as admin_views


urlpatterns = [
    path('user_permission', admin_views.UserPermissionViewSet.as_view({'post': 'create'}), name='add_user_permission'),
    path('logs', admin_views.LogViewSet.as_view({'get': 'retrieve'}), name='view_logs'),
    path('user/add', admin_views.AdminUserViewSet.as_view({'post': 'create'})),
    path('user/<int:user_id>/edit', admin_views.AdminUserViewSet.as_view({'put': 'update'})),
    path('user/list', admin_views.AdminUserViewSet.as_view({'get': 'list'})),
    path('user/<int:user_id>/info', admin_views.AdminUserViewSet.as_view({'get': 'retrieve'})),
    path('user/<int:user_id>/delete', admin_views.AdminUserViewSet.as_view({'delete': 'destroy'})),
]
