from django.urls import path, include
from rest_framework.routers import DefaultRouter
from users.views import UserViewSet, RegisterViewSet, ProfileViewSet, ResetPasswordViewSet, PasswordResetConfirmViewSet

router = DefaultRouter()
router.register('users', UserViewSet, basename='user')
router.register('register', RegisterViewSet, basename='user-registration')
router.register('reset_password', ResetPasswordViewSet, basename='reset')

urlpatterns = [
    path('password_reset_confirm/<uid64>/<token>/', PasswordResetConfirmViewSet.as_view({'post': 'create'}), name='password_reset_confirm'),
    path('users/me/', ProfileViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'})),
    path('', include(router.urls)),
]
