from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.core.cache import cache
from datetime import datetime
import os
from .models import UserEnrolled,Asset

@receiver(post_save, sender=UserEnrolled)
def book_change_handler(sender, instance, **kwargs):
    cache.set('has_changes', True)

@receiver(pre_delete, sender=UserEnrolled)
def book_delete_handler(sender, instance, **kwargs):
    cache.set('has_changes', True)


@receiver(post_save, sender=UserEnrolled)
def create_user_folder(sender, instance, created, **kwargs):
    if created:
        user_folder = os.path.join('media', 'facial_data', instance.get_folder_name())
        os.makedirs(user_folder, exist_ok=True)
