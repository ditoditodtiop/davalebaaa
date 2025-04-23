from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from rest_framework import mixins, viewsets, status, permissions, response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import action
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from users.serializers import UserSerializer, RegisterSerializer, ProfileSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer, EmailCodeResendSerializer, EmailCodeConfirmSerializer
from users.permissions import IsObjectOwnerOrReadOnly
from rest_framework.mixins import CreateModelMixin
from rest_framework.viewsets import GenericViewSet
from rest_framework.response import Response
from rest_framework import status
from users.models import EmailVerificationCode
from django.utils import timezone
from datetime import timedelta
import random
User = get_user_model()

class RegisterViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            self.send_verification_code(user)
            return Response(
                {"detail": "User registered successfully. Verification code sent to email."},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def send_verification_code(self, user):
        code = str(random.randint(100000, 999999))

        EmailVerificationCode.objects.update_or_create(
            user=user,
            defaults={'code': code, 'created_at': timezone.now()}
        )

        subject = "Your verification code"
        message = f"Hello {user.username},\n\nYour verification code is: {code}"

        send_mail(subject, message, 'no-reply@example.com', [user.email])

    @action(detail=False, methods=["post"], url_path="resend_code", serializer_class=EmailCodeResendSerializer)
    def resend_code(self, request):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data['user']
        existing_code = EmailVerificationCode.objects.filter(user=user).first()
        if existing_code:
            time_diff = timezone.now() - existing_code.created_at
            if time_diff < timedelta(minutes=1):
                wait_seconds = 60 - int(time_diff.total_seconds())
                return Response(
                    {"detail": f"Please wait {wait_seconds} seconds before requesting a new code."},
                    status=429
                )

        self.send_verification_code(user)
        return response.Response({"message": "Verification code resent successfully."})
    
    @action(detail=False, methods=['post'], url_path='confirm_code', serializer_class=EmailCodeConfirmSerializer)
    def confirm_code(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            user.is_active = True
            user.save()
            return response.Response({"message": "მომხმარებელი აღარ არის დაბლოკილი წარმატებით"}, status=status.HTTP_200_OK)
        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

class IsOwnerOrReadOnly(permissions.BasePermission):

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        
        return obj == request.user

class ProfileViewSet(viewsets.GenericViewSet, mixins.RetrieveModelMixin, mixins.UpdateModelMixin, mixins.DestroyModelMixin):
    serializer_class = ProfileSerializer
    permission_classes = [IsAuthenticated, IsObjectOwnerOrReadOnly]

    def get_object(self):
        return self.request.user

    @action(detail=False, methods=['get', 'put', 'patch', 'delete'], permission_classes=[IsAuthenticated, IsObjectOwnerOrReadOnly])
    def me(self, request):
        user = self.get_object()

        if request.method == 'GET':
            serializer = self.get_serializer(user)
            return Response(serializer.data)

        serializer = self.get_serializer(user, data=request.data, partial=request.method == 'PATCH')
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)

        if request.method == 'DELETE':
            user.delete()
            return Response(status=204)

        return Response(serializer.errors, status=400)

class ResetPasswordViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    serializer_class = PasswordResetSerializer

    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)

            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # reset_url = request.build_absolute_uri(
            #    reverse('password_reset_confirm', kwargs={"uid64":uid, "token":token})
            # )
            reset_url = f"http://127.0.0.1:8000/password_reset_confirm/{uid}/{token}/"
        
            send_mail(
                'recovery',
                f"click link to reset {reset_url}",
                "noreply@example.com",
                [user.email],
                fail_silently=False
            )

            return response.Response({"message": 'sent successfully'}, status=status.HTTP_200_OK)
        return response.Response(serializer.errors , status=status.HTTP_400_BAD_REQUEST)
    
class PasswordResetConfirmViewSet(CreateModelMixin, GenericViewSet):
    serializer_class = PasswordResetConfirmSerializer

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('uidb64', openapi.IN_PATH, description="User ID (Base64 encoded)", type=openapi.TYPE_STRING),
            openapi.Parameter('token', openapi.IN_PATH, description="Password reset token", type=openapi.TYPE_STRING),
        ]
    )
    def create(self, request, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "პაროლი წარმატებით განახლდა"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

