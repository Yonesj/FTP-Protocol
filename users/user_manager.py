import django
from users.models import User


class UserDBManager:
    @staticmethod
    def create_user(username, password, is_admin=False) -> User | None:
        if User.objects.filter(username=username).exists():
            return None  # User already exists

        user = User(
            username=username,
            password=password,
            is_admin=is_admin
        )
        user.save()
        return user

    @staticmethod
    def get_user(username):
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            return None


django.setup()
USER_DB_MANAGER = UserDBManager()
