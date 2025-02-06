import sys

import config
import django
from users.user_manager import USER_DB_MANAGER
from django.core.management import execute_from_command_line

# Initialize Django
django.setup()


def create_admin():
    username = input("Enter admin username: ")
    password = input("Enter admin password: ")

    admin = USER_DB_MANAGER.create_user(username, password, is_admin=True)
    if admin:
        print(f"Admin user '{username}' created successfully.")
    else:
        print(f"Admin user '{username}' already exists.")


def main():
    if sys.argv[1] == "createsuperuser":
        create_admin()
    else:
        execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
