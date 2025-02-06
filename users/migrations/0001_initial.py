# Generated by Django 5.1.4 on 2024-12-12 23:54

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=150, unique=True)),
                ('password', models.CharField(max_length=128)),
                ('can_read', models.BooleanField(default=False)),
                ('can_write', models.BooleanField(default=False)),
                ('can_delete', models.BooleanField(default=False)),
                ('can_create', models.BooleanField(default=False)),
            ],
        ),
    ]
