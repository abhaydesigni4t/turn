# Generated by Django 5.0.1 on 2024-08-19 10:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0033_alter_userenrolled_status'),
    ]

    operations = [
        migrations.AlterField(
            model_name='asset',
            name='status',
            field=models.CharField(choices=[('active', 'Active'), ('inactive', 'Inactive')], default='active', max_length=50),
        ),
    ]
