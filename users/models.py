from django.db import models


class User(models.Model):
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=128)
    can_read = models.BooleanField(default=False)
    can_write = models.BooleanField(default=False)
    can_delete = models.BooleanField(default=False)
    can_create = models.BooleanField(default=False)

    def __str__(self):
        return self.username
