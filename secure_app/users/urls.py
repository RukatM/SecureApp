from django.urls import path
from .views import login_view,register_view,dashboard_view,logout_view,home_view,add_message_view,password_reset_request_view,password_reset_view

urlpatterns = [
    
    path('', home_view, name='home'),
    path('register/', register_view, name='register'),
    path('login/', login_view, name='login'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('logout/', logout_view, name='logout'),
    path('add-message/', add_message_view, name='add_message'),
    path('password-reset-request/', password_reset_request_view, name='password_reset_request'),
    path('password-reset/', password_reset_view, name='password_reset'),
    
]