from django.urls import path
from accounts import views as account_views
urlpatterns = [
    # To call after sso success server is up
    # path('after_sso_success', account_views.AfterSsoSuccessViewSet.as_view({'get': 'retrieve'})),

    # To check server is up
    path('health', account_views.HealthViewSet.as_view({'get': 'retrieve'})),

    # To validate the token
    path('validate-token', account_views.ValidateTokenViewSet.as_view({'post': 'create'})),

    # User related APIs
    path('register', account_views.RegisterViewSet.as_view({'post': 'create'})),
    path('login', account_views.LoginViewSet.as_view({'post': 'create'})),
    path('password/update', account_views.UpdatePasswordViewSet.as_view({'patch': 'update'})),
    path('get-info', account_views.UserProfileViewSet.as_view({'get': 'retrieve'})),




    ]
