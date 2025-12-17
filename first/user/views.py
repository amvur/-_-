from http.client import responses
from rest_framework.views import APIView
from django.db.models import Q, Count
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from .seralizers import UserSerializer, UserCreateSerializer, UserUpdateSerializer, CustomTokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.views import TokenObtainPairView as SimpleJWTTokenRefreshView



User = get_user_model()

class RefreshTokenView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request, *args, **kwargs):
        try:
            return super().post(request, *args, **kwargs)
        except TokenError as e:
            return Response({
                'Error':  f"Invalid refresh token. {str(e)}",
            },
            status=status.HTTP_401_UNAUTHORIZED
            )



class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        return response



class UserViewSet(viewsets.ModelViewSet):
    """
    ViewSet для работы с пользователями.
    Предоставляет стандартные CRUD операции + кастомные actions.
    """
    queryset = User.objects.all().order_by('-date_joined')
    """Что делает:
User.objects.all() - выбирает ВСЕХ пользователей из базы
.order_by('-date_joined') - сортирует по дате регистрации в обратном порядке (новые первыми)"""
    permission_classes = [permissions.IsAuthenticated]  # Что означает: Аутентифицированные пользователи → могут делать всё (READ/WRITE) Анонимные пользователи → могут только читать (READ ONLY)

    def get_serializer_class(self):
        """
                Выбор сериализатора в зависимости от действия.
        :return:
        """
        if self.action == "create":
            return UserCreateSerializer  # Для создания
        elif self.action in ['update', 'partial_update']:
            return UserUpdateSerializer  # Для обновления
        else:
            return UserSerializer  # Для чтения и остального

    def get_permissions(self):
        """
              Настройка permissions в зависимости от действия.
              """
        if self.action in ['create', 'register', 'login']:
            return [permissions.AllowAny()]  # Регистрация доступна всем
        elif self.action in ['logout', 'me', 'change_password']:  # Изменение только для админов или владельцев
            return [permissions.IsAuthenticated()]
        elif self.action in ['update', 'partial_update']:
            # Endpoint /me/ только для авторизованных
            return [permissions.IsAuthenticated()]
        elif self.action == 'destroy':
            return [permissions.IsAdminUser()]
        elif self.action == 'stats':
            # Статистика только для админов
            return [permissions.IsAdminUser()]
        return super().get_permissions()

    def get_queryset(self):
        """Фильтрация queryset в зависимости от прав пользователя"""
        user = self.request.user
        if user.is_superuser:
            return User.objects.all()
        elif user.is_authenticated:
            # Обычный пользователи видят только свой профиль
            return User.objects.filter(id=user.id)
        return User.objects.none()

    def check_object_permissions(self, request, obj):
        """
        Дополнительная проверка: пользователь может редактировать только себя.
        """
        if self.action in ['update', 'partial_update', 'destroy']:
            if obj != request.user and not request.user.is_superuser:
                self.permission_denied(
                    request,
                    message="You can only edit your own profile."
                )
        super().check_object_permissions(request, obj)

    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def register(self, request):
        """
        Регистрация нового пользователя.
        POST /api/users/register/
        """
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()

            # Возвращаем данные пользователя и токены
            response_data = {
                'user': UserSerializer(user, context=self.get_serializer_context()).data,
                'tokens': serializer.get_tokens(user),
                'message': 'Registration successful'
            }

            return Response(response_data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def me(self, request):
        """
        Получение данных текущего пользователя.
        GET /api/users/me/
        """
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)

    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def login(self, request):
        """
        Альтернативный endpoint для логина.
        POST /api/users/login/
        """
        serializer = CustomTokenObtainPairSerializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def logout(self, request):
        """
        Логаут - добавление refresh токена в черный список.
        POST /api/users/logout/

        Body: {"refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."}
        """
        try:
            refresh_token = request.data.get("refresh")

            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            token = RefreshToken(refresh_token)
            token.blacklist()  # Добавляем в черный список

            # Можно также добавить логику для инвалидации access токена
            # (хотя он и так истечет через короткое время)

            return Response(
                {"message": "Successfully logged out"},
                status=status.HTTP_200_OK
            )

        except TokenError as e:
            return Response(
                {"error": f"Invalid token: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def me(self, request):
        """
                Кастомный endpoint для получения текущего пользователя.
                GET /api/users/me/
        """
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAdminUser, permissions.IsAuthenticated])
    def set_password(self, request, pk=None):
        """
                Кастомный endpoint для смены пароля.
                POST /api/users/{id}/set_password/
        """
        user = self.get_object()
        password = request.data.get("password")
        if password:
            user.set_password(password)
            user.save()
            return Response({'status': "password set"})
        return Response(
            {"Error": "Password not provided"},
            status=status.HTTP_400_BAD_REQUEST
        )

    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAdminUser])
    def stats(self, request):
        """
              Кастомный endpoint для статистики пользователей.
              GET /api/users/stats/
        """
        from django.db.models import Count
        stats = User.objects.aggregate(
            total_users=Count('id'),
            active_users=Count('id', filter=Q(is_active=True)),
            staff_users=Count('id', filter=Q(is_staff=True))
        )


        return Response(stats, status=status.HTTP_200_OK)


