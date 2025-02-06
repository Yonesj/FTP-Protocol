from django.db import models


class User(models.Model):
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=128)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return self.username
