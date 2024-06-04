from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.urls import reverse
from django.core.validators import FileExtensionValidator
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.hashers import make_password, check_password


class CustomUserManager(BaseUserManager):
    def create_user(self, username, email=None, password=None, **extra_fields):
        if not username:
            raise ValueError("The username field must be set")

        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)  # Hash the password
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(username, email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(unique=True)  # Add the email field
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email", "first_name", "last_name"]

    def __str__(self):
        return self.username

from django.core.validators import FileExtensionValidator

import os

def user_image_upload_path(instance, filename):
    base_filename, file_extension = os.path.splitext(filename)
    return f'facial_data/{instance.get_folder_name()}/{base_filename}{file_extension}'

class UserEnrolled(models.Model):
    sr = models.AutoField(primary_key=True,unique=True)
    name = models.CharField(max_length=255)
    company_name = models.CharField(max_length=100)
    job_role = models.CharField(max_length=100, choices=[
        ('role1', 'Role 1'),
        ('role2', 'Role 2'),
    ])
    mycompany_id = models.CharField(max_length=10)
    tag_id = models.CharField(max_length=50)
    job_location = models.CharField(max_length=100)
    orientation = models.FileField(upload_to='attachments/', blank=True,null=True, validators=[FileExtensionValidator(['jpeg', 'jpg'])])
    facial_data = models.ImageField(upload_to=user_image_upload_path, blank=True, null=True, verbose_name='Facial Data')
    my_comply = models.ImageField(upload_to='compliance_images/',blank=True, null=True)
    status = models.CharField(max_length=10, choices=[
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    ])
    email = models.EmailField()
    password = models.CharField(max_length=50)

    
    def __str__(self):
        return self.name

    def get_folder_name(self):
        return f"{self.name}_{self.tag_id}"
    
    def save(self, *args, **kwargs):
        if not self.pk: 
            last_instance = self.__class__.objects.last()
            if last_instance:
                self.sr = last_instance.sr + 1
            else:
                self.sr = 1
        super().save(*args, **kwargs)
    
    
class Notification(models.Model):
    sr = models.AutoField(primary_key=True,unique=True)
    subject = models.CharField(max_length=255)
    description = models.CharField(max_length=1000)
    username = models.CharField(max_length=255)

    def __str__(self):
        return self.subject

class Upload_data(models.Model):
    #uploaded_file = models.FileField(upload_to='uploads/') # it takes all files 
    uploaded_file = models.FileField(upload_to='uploads/', validators=[FileExtensionValidator(['pdf', 'doc', 'docx', 'jpeg', 'jpg'])])
  
    def __str__(self):
        return str(self.uploaded_file)
    
class Site_management(models.Model):
    link_field = models.URLField(max_length=200) 

class Asset(models.Model):
    asset_id = models.IntegerField(unique=True)
    asset_name = models.CharField(max_length=255)
    tag_id = models.IntegerField(unique=True)
    footage = models.ImageField(upload_to='assets_footage/', blank=True, null=True,verbose_name= 'Footage')
    description = models.CharField(max_length=500)
    asset_category = models.CharField(max_length=50)
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    ]
    status = models.CharField(max_length=50, choices=STATUS_CHOICES)
    location = models.CharField(max_length=100)
    time_log = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.asset_name

class check_changes(models.Model):
    name = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now=True) 
   
class Site(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class company(models.Model):
    sr = models.AutoField(primary_key=True,unique=True)
    name = models.CharField(max_length=100)
    works = models.CharField(max_length=100)
    safety_insurance = models.FileField(upload_to='attachments/', validators=[FileExtensionValidator(['pdf', 'doc', 'docx', 'jpeg', 'jpg'])])
    insurance_expiry = models.DateField()

    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        if not self.pk: 
            last_instance = self.__class__.objects.last()
            if last_instance:
                self.sr = last_instance.sr + 1
            else:
                self.sr = 1
        super().save(*args, **kwargs)

class timeschedule(models.Model):
    group = models.CharField(max_length=100)
    active_time = models.CharField(max_length=50)
    inactive_time = models.CharField(max_length=50)

    def __str__(self):
        return self.group
    
class Upload_File(models.Model):
    #uploaded_file = models.FileField(upload_to='uploads/') # it takes all files 
    uploaded_file = models.FileField(upload_to='uploads/', validators=[FileExtensionValidator(['pdf', 'doc', 'docx', 'jpeg', 'jpg'])])

class Turnstile_S(models.Model):
    sr_no = models.AutoField(primary_key=True,unique=True)
    turnstile_id = models.IntegerField(unique=True)
    location = models.CharField(max_length=100)
    safety_confirmation = models.BooleanField(default=False)

    def __str__(self):
        return str(self.turnstile_id)
    
    def save(self, *args, **kwargs):
        if not self.pk: 
            last_instance = self.__class__.objects.last()
            if last_instance:
                self.sr_no = last_instance.sr_no + 1
            else:
                self.sr_no = 1
        super().save(*args, **kwargs)

class Orientation(models.Model):
    attachments = models.FileField(upload_to='attachments/', validators=[FileExtensionValidator(['pdf'])])

class PreShift(models.Model):
    document = models.FileField(upload_to='preshift/') 
    date = models.DateField(auto_now_add=True) 

class ToolBox(models.Model):
    document = models.FileField(upload_to='toolbox/') 
    date = models.DateField(auto_now_add=True) 

class OnSiteUser(models.Model):
    name = models.CharField(max_length=100)
    tag_id = models.CharField(max_length=50)
    status = models.CharField(max_length=100, choices=[
        ('Entry', 'Entry'),
        ('Exit', 'Exit'),
    ])
    timestamp = models.DateTimeField(auto_now=True) 

    def __str__(self):
        return self.name