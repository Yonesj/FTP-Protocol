# Generated by Django 5.1.4 on 2024-12-25 14:14

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('users', '0002_rename_can_create_user_is_admin_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='FileMetaData',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=128)),
                ('path', models.CharField(max_length=500, unique=True)),
                ('is_public', models.BooleanField(default=False)),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='files', to='users.user')),
            ],
        ),
    ]
