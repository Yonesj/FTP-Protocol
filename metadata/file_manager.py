import django
from .models import FileMetaData


class FileDBManager:
    @staticmethod
    def create_file(name, path, user, is_public=False) -> FileMetaData | None:
        if FileMetaData.objects.filter(path=path).exists():
            return None  # User already exists

        metadata = FileMetaData(
            name=name,
            path=path,
            owner=user,
            is_public=is_public
        )
        metadata.save()
        return metadata

    @staticmethod
    def get_file(path) -> FileMetaData | None:
        try:
            return FileMetaData.objects.get(path=path)
        except FileMetaData.DoesNotExist:
            return None

    @staticmethod
    def delete_file(file: FileMetaData | None) -> None:
        try:
            if file is not None:
                file.delete()
        except RuntimeError:
            pass


django.setup()
FILE_DB_MANAGER = FileDBManager()
