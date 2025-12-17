from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()




class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):


    def validate(self, attrs):
        data = super().validate(attrs)

        user = self.user

        data['user'] = {
            'id': user.id,
            'email': user.email,
            'view': user.view,
            'name_firma': user.name_firma,
            'inn': user.inn,
            'kPP': user.kPP,
        }

        data["message"] = 'login successful'
        data["token_type"] = "Bearer"
        return data
    @classmethod
    def get_token(self, user):

        token = super().get_token(user)
        token['email'] = user.get_email_field_name()
        return token


class UserSerializer(serializers.ModelSerializer):
    """
        Сериализатор для чтения данных пользователя.
    """

    class Meta:
        model = User
        fields = [
            'id', 'email', 'view', 'name_firma', 'inn',
            'kPP', 'Address', 'director', 'is_active',       #  fields - какие поля включаются:
            'inn', 'kPP', 'Address', 'director',
            'is_staff', 'date_joined', 'last_login'
        ]
        read_only_fields = ['id', 'date_joined', 'last_login']


class UserCreateSerializer(serializers.ModelSerializer):
    """
    Сериализатор для создания данных пользователя.
    """
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        validators=[validate_password]
    )
    password2 = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
    )
    tokens = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = User
        fields = [
            'email', 'password', 'password2', 'view', 'name_firma',
            'inn', 'kPP', 'Address', 'director'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'password2': {'write_only': True},
        }

    # ✅ Методы должны быть НА УРОВНЕ КЛАССА, не внутри Meta!
    def validate(self, attrs):
        """
        Проверяет совпадение паролей.
        """
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        """
        Создает пол ьзователя с хэшированным паролем.
        """
        # Извлекаем и удаляем служебные поля
        password = validated_data.pop('password')
        validated_data.pop('password2')  # Просто удаляем, не используем

        # Создаем пользователя
        user = User.objects.create(**validated_data)

        # Устанавливаем пароль (автоматически хэшируется)
        user.set_password(password)
        user.save()

        return user


    def get_token(self, odj):
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(odj)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),

        }

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'view', 'name_firma', 'inn', 'kPP',
            'Address', 'director', 'is_active'
        ]


