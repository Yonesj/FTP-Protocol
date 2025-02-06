from django.db import models
from users.models import User


class FileMetaData(models.Model):
    name = models.CharField(max_length=128)
    path = models.CharField(max_length=500, unique=True)
    owner = models.ForeignKey(User, related_name="files", on_delete=models.CASCADE)
    is_public = models.BooleanField(default=False)

    def __str__(self):
        return self.name
