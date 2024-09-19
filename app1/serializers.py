from rest_framework import serializers
from .models import UserEnrolled,Asset,Site,Notification,Upload_File,Turnstile_S,Orientation,PreShift,ToolBox



class ActionStatusSerializer(serializers.Serializer):
    status = serializers.IntegerField()

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    
    
class AssetSerializer(serializers.ModelSerializer):
    picture = serializers.ImageField(max_length=None, use_url=True, required=False)
    footage = serializers.ImageField(max_length=None, use_url=True, required=False)
    site = serializers.CharField()  # Field to accept site name

    class Meta:
        model = Asset
        fields = [ 'picture', 'asset_name', 'tag_id', 'footage', 'description', 'status', 'location', 'time_log', 'site']

    def validate_site(self, value):
        try:
            site_instance = Site.objects.get(name=value.upper())
            return site_instance
        except Site.DoesNotExist:
            raise serializers.ValidationError("Site with this name does not exist.")

    def create(self, validated_data):
        site = validated_data.pop('site')
        asset = Asset.objects.create(site=site, **validated_data)
        return asset
    
from django.conf import settings
from django.core.files.storage import default_storage
from django.core.exceptions import ValidationError


class UserEnrolledSerializer(serializers.ModelSerializer):
    picture = serializers.SerializerMethodField()
    site = serializers.SerializerMethodField()

    class Meta:
        model = UserEnrolled
        exclude = ['sr', 'password']
        extra_kwargs = {
            'email': {'validators': []},  # Remove default unique validator
        }

    def get_picture(self, obj):
        request = self.context.get('request')
        user_folder = os.path.join(settings.MEDIA_ROOT, 'facial_data', obj.get_folder_name())
        if default_storage.exists(user_folder):
            user_images = [f for f in default_storage.listdir(user_folder)[1] if f.endswith('.jpg') or f.endswith('.jpeg')]
            if user_images:
                image_path = os.path.join('facial_data', obj.get_folder_name(), user_images[0])
                image_url = request.build_absolute_uri(settings.MEDIA_URL + image_path)
                return image_url
        return None

    def get_site(self, obj):
        if obj.site:
            return obj.site.name  # Assuming the Site model has a 'name' field
        return None

    def validate_email(self, value):
        if UserEnrolled.objects.filter(email=value).exists():
            raise ValidationError("This email already exists.")
        return value
    
class UserEnrolledSerializer1(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ['email','tag_id']
       
class UserEnrolledSerializer2(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ['mycompany_id','orientation']

from django.utils import timezone

class ExitSerializer(serializers.ModelSerializer):
    time_log = serializers.DateTimeField(default=serializers.DateTimeField())
    site = serializers.CharField(required=True)  # Site name will be passed in the form data

    class Meta:
        model = Asset
        fields = ['asset_name', 'tag_id', 'footage', 'location', 'time_log', 'site']
        read_only_fields = ['time_log']  # Ensuring time_log is read-only as it is automatically set

    def create(self, validated_data):
        # Convert empty string to null for location
        if validated_data.get('location') == '':
            validated_data['location'] = None
        return super().create(validated_data)

    def validate_site(self, value):
        # Validate if the site exists
        if not Site.objects.filter(name__iexact=value).exists():
            raise serializers.ValidationError('Site does not exist.')
        return value

class SiteSerializer(serializers.ModelSerializer):
    picture = serializers.SerializerMethodField()

    class Meta:
        model = Site
        fields = ['picture', 'name', 'location', 'total_users', 'active_users', 'inactive_users']

    def get_picture(self, obj):
        request = self.context.get('request')
        if obj.picture:
            return request.build_absolute_uri(obj.picture.url)
        return None

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['subject', 'description', 'username']

class UploadedFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Upload_File
        fields = '__all__'

class TurnstileSerializer(serializers.ModelSerializer):
    safety_confirmation = serializers.SerializerMethodField()

    def get_safety_confirmation(self, obj):
        return 1 if obj.safety_confirmation else 0

    class Meta:
        model = Turnstile_S
        fields = ['turnstile_id', 'location', 'safety_confirmation']

class AssetStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = ['asset_id', 'status','location']

class facialDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ('email', 'facial_data')


from rest_framework import serializers

class OrientationSerializer(serializers.ModelSerializer):
    site = serializers.SlugRelatedField(
        queryset=Site.objects.all(),
        slug_field='name',  # Assuming 'name' is the field in the Site model you want to query by
    )

    def to_internal_value(self, data):
        # Perform case-insensitive lookup for the 'site' field
        if 'site' in data:
            site_name = data['site']
            try:
                site = Site.objects.get(name__iexact=site_name)
                data['site'] = site
            except Site.DoesNotExist:
                raise serializers.ValidationError({'site': ['Site not found.']})
        return super().to_internal_value(data)

    class Meta:
        model = Orientation
        fields = '__all__'
 
    

class GetOrientationSerializer(serializers.ModelSerializer):
    attachment_url = serializers.SerializerMethodField()
    site_name = serializers.SerializerMethodField()

    class Meta:
        model = Orientation
        fields = ['attachment_url', 'site_name']

    def get_attachment_url(self, obj):
        request = self.context.get('request')
        return obj.attachments.url if request else None

    def get_site_name(self, obj):
        return obj.site.name


from rest_framework import serializers
from .models import PreShift, Site

class PreShiftSerializer(serializers.ModelSerializer):
    site = serializers.CharField()

    class Meta:
        model = PreShift
        fields = ['document', 'date', 'site']

    def validate_site(self, value):
        try:
            return Site.objects.get(name__iexact=value)
        except Site.DoesNotExist:
            raise serializers.ValidationError("Site with this name does not exist.")

    def create(self, validated_data):
        site_name = validated_data.pop('site')
        site = Site.objects.get(name__iexact=site_name)
        return PreShift.objects.create(site=site, **validated_data)

from rest_framework import serializers
from .models import ToolBox, Site

class ToolBoxSerializer(serializers.ModelSerializer):
    site = serializers.CharField()

    class Meta:
        model = ToolBox
        fields = ['document', 'date', 'site']

    def validate_site(self, value):
        try:
            return Site.objects.get(name__iexact=value)
        except Site.DoesNotExist:
            raise serializers.ValidationError("Site with this name does not exist.")

    def create(self, validated_data):
        site_name = validated_data.pop('site')
        site = Site.objects.get(name__iexact=site_name)
        return ToolBox.objects.create(site=site, **validated_data)



from rest_framework import serializers

class FacialImageDataSerializer(serializers.Serializer):
    email = serializers.EmailField()
    facial_data = serializers.ListField(child=serializers.ImageField())


# serializers.py
from rest_framework import serializers
from .models import UserEnrolled, Site

class UserProfileSerializer(serializers.ModelSerializer):
    site = serializers.CharField(required=False, allow_blank=True)  # Change to CharField for site name

    class Meta:
        model = UserEnrolled
        fields = ['name', 'company_name', 'job_role', 'mycompany_id', 'job_location', 'email', 'site']
    
    def create(self, validated_data):
        validated_data['status'] = 'pending'
        return UserEnrolled.objects.create(**validated_data)

    def update(self, instance, validated_data):
        validated_data['status'] = validated_data.get('status', 'pending')
        return super().update(instance, validated_data)


from django.utils import timezone
from django.utils.dateparse import parse_date

from django.utils.dateparse import parse_date
from rest_framework import serializers
from django.utils import timezone
from datetime import datetime

class UserComplySerializer(serializers.ModelSerializer):
    expiry_date = serializers.CharField(required=False)  # Keep as string for parsing

    class Meta:
        model = UserEnrolled
        fields = ['email', 'my_comply', 'mycompany_id', 'expiry_date']

    def validate_expiry_date(self, value):
        if value:
            if isinstance(value, str):  # Ensure value is a string
                for date_format in ['%m/%d/%Y', '%m-%d-%Y']:
                    try:
                        # Try parsing the date with the current format
                        parsed_date = datetime.strptime(value, date_format).date()
                        
                        if parsed_date < timezone.now().date():
                            raise serializers.ValidationError("Expiry date cannot be in the past.")
                        
                        return parsed_date  # Return the parsed date if successful
                    except ValueError:
                        continue  # Try the next format
                
                # If none of the formats worked, raise a validation error
                raise serializers.ValidationError("Invalid date format. Use MM/DD/YYYY or MM-DD-YYYY.")
            else:
                raise serializers.ValidationError("Expiry date must be a string.")
        return value


from rest_framework import serializers
from .models import OnSiteUser


# class OnSiteUserSerializer(serializers.ModelSerializer):
#     site = serializers.CharField(required=False)

#     class Meta:
#         model = OnSiteUser
#         fields = ['name', 'tag_id', 'status', 'site']

#     def to_internal_value(self, data):
#         # Convert site name to Site instance
#         internal_data = super().to_internal_value(data)
#         site_name = data.get('site')

#         if site_name:
#             try:
#                 site = Site.objects.get(name=site_name)
#                 internal_data['site'] = site
#             except Site.DoesNotExist:
#                 raise serializers.ValidationError({'site': 'Site with the provided name does not exist.'})
#         else:
#             internal_data['site'] = None
        
#         return internal_data

#     def to_representation(self, instance):
#         # Convert Site instance to site name for the response
#         representation = super().to_representation(instance)
#         representation['site'] = instance.site.name if instance.site else None
#         return representation

class OnSiteUserSerializer(serializers.ModelSerializer):
    site = serializers.CharField(required=False)
    face = serializers.BooleanField(required=True)  # Include the face field in the serializer

    class Meta:
        model = OnSiteUser
        fields = ['name', 'tag_id', 'status', 'site', 'face']  # Add face to the fields list

    def to_internal_value(self, data):
        # Convert site name to Site instance
        internal_data = super().to_internal_value(data)
        site_name = data.get('site')

        if site_name:
            try:
                site = Site.objects.get(name=site_name)
                internal_data['site'] = site
            except Site.DoesNotExist:
                raise serializers.ValidationError({'site': 'Site with the provided name does not exist.'})
        else:
            internal_data['site'] = None
        
        return internal_data

    def to_representation(self, instance):
        # Convert Site instance to site name for the response
        representation = super().to_representation(instance)
        representation['site'] = instance.site.name if instance.site else None
        representation['face'] = 1 if instance.face else 0  # Convert boolean to 0 or 1
        return representation


        
    
'''    
        
# this is correct post onsite user api post data using site only do this changes in serializer 

class OnSiteUserSerializer(serializers.ModelSerializer):
    site = serializers.CharField()

    class Meta:
        model = OnSiteUser
        fields = ['name', 'tag_id', 'status', 'site']

    def validate_site(self, value):
        try:
            return Site.objects.get(name__iexact=value)
        except Site.DoesNotExist:
            raise serializers.ValidationError("Site with this name does not exist.")

    def create(self, validated_data):
        site_name = validated_data.pop('site')
        site = Site.objects.get(name__iexact=site_name)
        return OnSiteUser.objects.create(site=site, **validated_data)
        '''

class OnsiteGetSerializer(serializers.ModelSerializer):
    site = serializers.SerializerMethodField()

    class Meta:
        model = OnSiteUser
        fields = ['name', 'tag_id', 'status', 'face', 'timestamp', 'site']

    def get_site(self, obj):
        # Return the site name instead of the primary key
        return obj.site.name if obj.site else None

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        # Convert the boolean face field to 1 or 0
        representation['face'] = 1 if instance.face else 0
        return representation



class PostSiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Site
        fields = ['picture', 'name', 'location']
        
        
class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
import os
from django.conf import settings

class GetUserEnrolledSerializer(serializers.ModelSerializer):
    picture = serializers.SerializerMethodField()
    orientation = serializers.SerializerMethodField()
    facial_data = serializers.SerializerMethodField()
    my_comply = serializers.SerializerMethodField()

    class Meta:
        model = UserEnrolled
        fields = ['picture', 'name', 'company_name', 'job_role', 'mycompany_id', 'tag_id', 'job_location', 'orientation', 'facial_data', 'my_comply', 'status', 'email']

    def get_picture(self, obj):
        request = self.context.get('request')
        user_folder = os.path.join(settings.MEDIA_ROOT, 'facial_data', obj.get_folder_name())

        if os.path.exists(user_folder):
            user_images = [f for f in os.listdir(user_folder) if f.endswith('.jpg') or f.endswith('.jpeg')]
            if user_images:
                image_path = os.path.join('facial_data', obj.get_folder_name(), user_images[0])
                return request.build_absolute_uri(settings.MEDIA_URL + image_path)
        return None

    def get_orientation(self, obj):
        request = self.context.get('request')
        if obj.orientation and os.path.isfile(os.path.join(settings.MEDIA_ROOT, obj.orientation.name)):
            return request.build_absolute_uri(settings.MEDIA_URL + obj.orientation.name)
        return None

    def get_facial_data(self, obj):
        request = self.context.get('request')
        user_folder = os.path.join(settings.MEDIA_ROOT, 'facial_data', obj.get_folder_name())

        if os.path.exists(user_folder):
            user_images = [f for f in os.listdir(user_folder) if f.endswith('.jpg') or f.endswith('.jpeg')]
            if user_images:
                image_path = os.path.join('facial_data', obj.get_folder_name(), user_images[0])
                return request.build_absolute_uri(settings.MEDIA_URL + image_path)
        return None

    def get_my_comply(self, obj):
        request = self.context.get('request')
        if obj.my_comply and os.path.isfile(os.path.join(settings.MEDIA_ROOT, obj.my_comply.name)):
            return request.build_absolute_uri(settings.MEDIA_URL + obj.my_comply.name)
        return None

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        for field in ['picture', 'orientation', 'facial_data', 'my_comply']:
            if representation[field] is None:
                representation[field] = None
        return representation
    
    
from django.contrib.auth.hashers import make_password
from rest_framework import serializers
from .models import UserEnrolled

class UserEnrolledSerializer11(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ('name', 'company_name', 'job_role', 'mycompany_id', 'tag_id', 'job_location', 'status', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        # Hash the password before saving
        validated_data['password'] = make_password(validated_data['password'])
        return UserEnrolled.objects.create(**validated_data)


class UserEnrolledUpdateSerializer11(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ('name', 'company_name', 'job_role', 'mycompany_id', 'tag_id', 'job_location', 'status', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def update(self, instance, validated_data):
        # Hash the password if it's being updated
        password = validated_data.pop('password', None)
        if password:
            instance.set_password(password)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class SignUpSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ['name', 'email', 'password']
    
    def validate_password(self, value: str) -> str:
        """Hash the password before saving."""
        return make_password(value)



from django.contrib.auth.hashers import check_password


class AdminLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")
        
        if email and password:
            try:
                user = UserEnrolled.objects.get(email=email)
            except UserEnrolled.DoesNotExist:
                raise serializers.ValidationError("Invalid email or password.")
            
            if not check_password(password, user.password):
                raise serializers.ValidationError("Invalid email or password.")
        else:
            raise serializers.ValidationError("Both email and password are required.")
        
        data["user"] = user
        return data

from django.contrib.auth import get_user_model

class SignupSerializer_new(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('email', 'password', 'name', 'company_name', 'job_role', 'mycompany_id', 'tag_id', 'job_location')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = get_user_model().objects.create_user(**validated_data)
        return user
    
    
class LoginSerializer_new(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, data):
        email = data.get('email').lower()  # Convert to lowercase
        password = data.get('password')
        user = get_user_model().objects.filter(email=email).first()
        if user and user.check_password(password):
            data['user'] = user
            return data
        raise serializers.ValidationError('Incorrect email or password.')

class UserSerializer_new(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('email', 'name', 'company_name', 'job_role', 'mycompany_id', 'tag_id', 'job_location')
        
        
class signup_app(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ['name', 'email', 'password']
        
        
class LoginSerializerApp(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            raise serializers.ValidationError("Both email and password are required.")

        user = UserEnrolled.objects.filter(email=email, password=password).first()
        if not user:
            raise serializers.ValidationError("Invalid email or password.")

        return data
    

from rest_framework_simplejwt.tokens import RefreshToken

class LoginSerializerApp1(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            raise serializers.ValidationError("Both email and password are required.")

        user = UserEnrolled.objects.filter(email=email, password=password).first()
        if not user:
            raise serializers.ValidationError("Invalid email or password.")

        # Generate JWT token (if you want to do it here)
        refresh = RefreshToken.for_user(user)
        data['token'] = str(refresh.access_token)
        data['refresh_token'] = str(refresh)

        return data


from django.contrib.auth import get_user_model
from rest_framework import serializers

class SignupUserRetrieveSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('email', 'name', 'company_name', 'job_role', 'mycompany_id', 'tag_id', 'job_location')
        # Note: You may want to exclude or include other fields as necessary
        
class SignupUserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('email', 'name', 'company_name', 'job_role', 'mycompany_id', 'tag_id', 'job_location')
        read_only_fields = ('date_joined',)  # Prevent updating these fields

    


class UserEnrolledSerializerExpiry(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ('email', 'name', 'my_comply', 'expiry_date')
        extra_kwargs = {
            'email': {'required': True},
            'name': {'required': True},
            'my_comply': {'required': False},
            'expiry_date': {'required': True}
        }

    def validate_email(self, value):
        # Check if the user exists
        try:
            user = UserEnrolled.objects.get(email=value)
            return user
        except UserEnrolled.DoesNotExist:
            raise serializers.ValidationError('User with this email does not exist.')
        
'''   
        
from rest_framework import serializers

class UpdateEnrolledSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        exclude = ['password']

'''
        
    
class BulkUpdateByEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    status = serializers.ChoiceField(choices=[
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    ])
    
    
    
    
class UserEnrolledSerializer_update(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = '__all__'  # Or specify the fields you want to include
        read_only_fields = ('password',)

    def get_site_name(self, obj):
        return obj.site.name if obj.site else None
    


from rest_framework import serializers
from .models import Turnstile_S

class TurnstileUnlockSerializer(serializers.ModelSerializer):
    unlock = serializers.SerializerMethodField()

    class Meta:
        model = Turnstile_S
        fields = ['turnstile_id', 'unlock']

    def get_unlock(self, obj):
        """Convert the boolean field to 0 or 1."""
        return 1 if obj.unlock else 0


from django.conf import settings

from rest_framework import serializers
from django.db.models import Count, Q

class SubAdminSiteSerializer(serializers.ModelSerializer):
    picture_url = serializers.SerializerMethodField()
    total_user = serializers.SerializerMethodField()
    active_user = serializers.SerializerMethodField()
    inactive_user = serializers.SerializerMethodField()

    class Meta:
        model = Site
        fields = ['picture_url', 'name', 'location', 'total_user', 'active_user', 'inactive_user']

    def get_picture_url(self, obj):
        request = self.context.get('request')
        if obj.picture and request:
            return request.build_absolute_uri(obj.picture.url)
        return None

    def get_total_user(self, obj):
        return UserEnrolled.objects.filter(site=obj).count()

    def get_active_user(self, obj):
        return UserEnrolled.objects.filter(site=obj, status='active').count()

    def get_inactive_user(self, obj):
        return UserEnrolled.objects.filter(site=obj, status='inactive').count()


class UserWithSiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ['picture', 'name', 'company_name', 'job_role', 'mycompany_id', 'tag_id', 'job_location', 'orientation', 'facial_data', 'my_comply', 'expiry_date', 'status', 'email','site']

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        
        rep['site'] = instance.site.name
        
        request = self.context.get('request')
        
        if instance.picture:
            rep['picture'] = request.build_absolute_uri(instance.picture.url)
        
        if instance.orientation:
            rep['orientation'] = request.build_absolute_uri(instance.orientation.url)
        
        if instance.facial_data:
            rep['facial_data'] = request.build_absolute_uri(instance.facial_data.url)
        
        if instance.my_comply:
            rep['my_comply'] = request.build_absolute_uri(instance.my_comply.url)
        
        return rep
    
    
class PendingUserWithSiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ['picture', 'name', 'company_name', 'job_role', 'mycompany_id', 'tag_id', 'job_location', 'orientation', 'facial_data', 'my_comply', 'expiry_date', 'status', 'email','site']  

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        
        rep['site'] = instance.site.name
        
        request = self.context.get('request')
        
        if instance.picture:
            rep['picture'] = request.build_absolute_uri(instance.picture.url)
        
        if instance.orientation:
            rep['orientation'] = request.build_absolute_uri(instance.orientation.url)
        
        if instance.facial_data:
            rep['facial_data'] = request.build_absolute_uri(instance.facial_data.url)
        
        if instance.my_comply:
            rep['my_comply'] = request.build_absolute_uri(instance.my_comply.url)
        
        return rep


class NotTagUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ('sr', 'name', 'company_name', 'job_role', 'mycompany_id', 'job_location', 'status', 'email')  # Include only the fields you want to expose
        
        
    
    
class AppleUserEnrolledSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = [
            'name',
            'email',
            'password',
            'identity_token',
        ]
        read_only_fields = ['sr']  # AutoField should be read-only

    def create(self, validated_data):
        # Create a new user instance
        user = UserEnrolled(
            name=validated_data.get('name'),
            email=validated_data.get('email'),
            identity_token=validated_data.get('identity_token'),
            # Set other fields as needed
        )
        user.set_password(validated_data.get('password', 'default_password'))  # Set a default password if not provided
        user.save()
        return user

    def update(self, instance, validated_data):
        # Update an existing user instance
        instance.name = validated_data.get('name', instance.name)
        instance.email = validated_data.get('email', instance.email)
        instance.identity_token = validated_data.get('identity_token', instance.identity_token)
        # Update other fields as needed
        instance.save()
        return instance