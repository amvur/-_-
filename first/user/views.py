import logging

from django.contrib.auth import authenticate, logout
from rest_framework.permissions import AllowAny
from .models import CustomUser, UserProfile
from .seralizers import CustomUserSerializer, UserSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics, permissions
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token

logger = logging.getLogger(__name__)

class GetCustomUserApi(APIView):
    def get(self, request):
        users = CustomUser.objects.all()
        return Response(
            {
                'user':users
            },
            status= status.HTTP_200_OK
        )

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)

        if not serializer.is_valid():
            logger.error(f'Ошибка формы {serializer.errors}')
            return Response(
                {
                    "error": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            user = serializer.save()
            UserProfile.objects.create(user=user)
            return Response(
                {
                    "success": "User created successfully",
                    "user_id": user.id,
                    "email": user.email
                },

                # CustomUserSerializer(user).data,
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            logger.error(f'Ошибка создании профиля: {str(e)}', exc_info=True)
            return Response(
                {
                    "error" :"profile create failed"
                },
                status =status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CustomAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        email =request.data.get('email')
        password = request.data.get('password')
        if not email or not password:
            return Response(
                {"error": "Необходимо указать email и пароль"},
                status=status.HTTP_400_BAD_REQUEST
            )
        user = authenticate(email=email, password=password)
        if not user:
            return Response(
                {"error": "Неверные учетные данные"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        token, create = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user': CustomUserSerializer(user).data
        })
class LogoutView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        request.user.auth_token.delete()
        logout(request)
        return Response(status=204)
