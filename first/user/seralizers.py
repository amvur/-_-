from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.tokens import RefreshToken


users = get_user_model()




class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):


    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user
        data['user'] = {
            'id': user.id,
            'email': user.email,
            'view': getattr(user, 'view',None),
            'name_firma':getattr( user, 'name_firma', None),
            'inn': getattr(user, 'inn', None),
            'kPP': getattr(user, 'kPP', None),
        }

        data["message"] = 'login successful'
        data["token_type"] = "Bearer"
        return data
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['email'] = user.email
        return token


class UserSerializer(serializers.ModelSerializer):
    """
        Сериализатор для чтения данных пользователя.
    """

    class Meta:
        model = users
        fields = [
            'id', 'email', 'view', 'name_firma', 'inn',
            'kPP', 'Address', 'director', 'is_active',       #  fields - какие поля включаются:
            'inn', 'kPP', 'Address', 'director',
            'is_staff', 'date_joined', 'last_login'
        ]
        read_only_fields = ['id', 'date_joined', 'last_login']


class UserCreateSerializer(serializers.Serializer):
    """
    Сериализатор только для регистрации.
    """
    username = serializers.CharField(required=False)

    email = serializers.EmailField(required=True)
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


    # view = serializers.ChoiceField(choices=users.VIEW, required=True)
    # name_firma = serializers.CharField(required=float)
    # inn = serializers.CharField(required=False)
    # kPP = serializers.CharField(required=False)
    # Address = serializers.CharField(required=False)
    # tokens = serializers.SerializerMethodField(read_only=False)

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        # Проверяем, что email не занят
        if users.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError({"email": "User with this email already exists."})

        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password')
        validated_data.pop('password2')

        user = users.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user

    def get_tokens(self, obj):
        refresh = RefreshToken.for_user(obj)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

    def to_representation(self, instance):
        """
        Переопределяем вывод, чтобы включить токены.
        """
        data = super().to_representation(instance)
        data['tokens'] = self.get_tokens(instance)
        return data

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = users
        fields = [
            'view', 'name_firma', 'inn', 'kPP',
            'Address', 'director', 'is_active'
        ]


