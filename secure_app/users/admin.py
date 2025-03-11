from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser,Message

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'username', 'is_staff', 'is_active', 'last_login')
    ordering = ('email',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('username',)}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'groups', 'user_permissions')}),
        ('Important Dates', {'fields': ('last_login', 'date_joined')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2', 'is_staff', 'is_active')}
        ),
    )

    search_fields = ('email', 'username')

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ("user", "content", "created_at")
    search_fields = ("user__email", "content")
    list_filter = ("created_at",)

    