import django
from django.core.management import call_command
from users.models import User


django.setup()
call_command("makemigrations", "users")
call_command("migrate")


class UserDBManager:
    @staticmethod
    def create_user(username, password) -> User | None:
        if User.objects.filter(username=username).exists():
            return None  # User already exists

        user = User(
            username=username,
            password=password,
            can_read=True,
            can_write=False,
            can_delete=False,
            can_create=True,
        )
        user.save()
        return user

    @staticmethod
    def create_admin(username, password) -> User | None:
        """
        Creates an admin user with all permissions enabled.
        This method can only be called via command line.
        """
        if User.objects.filter(username=username).exists():
            return None  # User already exists

        user = User(
            username=username,
            password=password,
            can_read=True,
            can_write=True,
            can_delete=True,
            can_create=True,
        )
        user.save()
        print(f"Admin user '{username}' created successfully.")
        return user

    @staticmethod
    def get_user(username):
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            return None


USER_DB_MANAGER = UserDBManager()
