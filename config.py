import os
import django
from django.conf import settings

# Configure Django settings
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME', 'ftps_db'),
        'USER': os.getenv('DB_USER', ''),
        'PASSWORD': os.getenv('DB_PASSWORD', ''),
        'HOST': os.getenv('DB_HOST', 'localhost'),
        'PORT': os.getenv('DB_PORT', '5432'),
    }
}

if not settings.configured:
    settings.configure(
        DATABASES=DATABASES,
        INSTALLED_APPS=['users', 'metadata'],
        DEFAULT_AUTO_FIELD='django.db.models.BigAutoField',
    )

# Initialize Django
django.setup()
