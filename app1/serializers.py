from rest_framework import serializers
from .models import UserEnrolled,Asset,Site,Notification,Upload_File,Turnstile_S,Orientation,PreShift,ToolBox



class ActionStatusSerializer(serializers.Serializer):
    status = serializers.IntegerField()

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class AssetSerializer(serializers.ModelSerializer):
    picture = serializers.SerializerMethodField()
    footage = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = ['asset_id','picture','asset_name','tag_id','footage','description','asset_category','status','location','time_log']

    def get_picture(self, obj):
        return self.check_file_exists(obj.picture)

    def get_footage(self, obj):
        return self.check_file_exists(obj.footage)

    def check_file_exists(self, file_field):
        if file_field and os.path.isfile(os.path.join(settings.MEDIA_ROOT, file_field.name)):
            request = self.context.get('request')
            return request.build_absolute_uri(settings.MEDIA_URL + file_field.name)
        return 0


class UserEnrolledSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ['picture','name','company_name','job_role','mycompany_id','tag_id','job_location','orientation','status']

    def get_picture(self, obj):
        user_folder = os.path.join('media', 'facial_data', obj.get_folder_name())
        if os.path.exists(user_folder):
            user_images = [f for f in os.listdir(user_folder) if f.endswith('.jpg') or f.endswith('.jpeg')]
            if user_images:
                return os.path.join('facial_data', obj.get_folder_name(), user_images[0])
        return None
    
class UserEnrolledSerializer1(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ['email','tag_id']
       
class UserEnrolledSerializer2(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ['mycompany_id','orientation']

class ExitSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        exclude = ['id']

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

class OrientationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Orientation
        fields = '__all__'
    
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

class signup_app(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ['name', 'email', 'password']

class PreShiftSerializer(serializers.ModelSerializer):
    class Meta:
        model = PreShift
        fields = ['document', 'date']

class ToolBoxSerializer(serializers.ModelSerializer):
    class Meta:
        model = ToolBox
        fields = ['document', 'date']


from rest_framework import serializers

class FacialImageDataSerializer(serializers.Serializer):
    email = serializers.EmailField()
    facial_data = serializers.ListField(child=serializers.ImageField())


# serializers.py
from rest_framework import serializers
from .models import UserEnrolled

class UserProfileSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = UserEnrolled
        fields = ['name', 'company_name', 'job_role', 'mycompany_id', 'job_location', 'email']
       
    def create(self, validated_data):
        validated_data['status'] = 'active'
        return UserEnrolled.objects.create(**validated_data)

    def update(self, instance, validated_data):
        validated_data['status'] = validated_data.get('status', 'active')
        return super().update(instance, validated_data)

class UserComplySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserEnrolled
        fields = ['email', 'my_comply']


from rest_framework import serializers
from .models import OnSiteUser

class OnSiteUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = OnSiteUser
        fields = ['name', 'tag_id', 'status']


class OnsiteGetSerializer(serializers.ModelSerializer):
    class Meta:
        model = OnSiteUser
        fields = ['name', 'tag_id', 'status', 'timestamp']


class PostSiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Site
        fields = ['picture', 'name', 'location']
        
        
class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
import os
from django.conf import settings

class GetUserEnrolledSerializer(serializers.ModelSerializer):
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
        if obj.orientation:
            return request.build_absolute_uri(settings.MEDIA_URL + obj.orientation.name)
        return None

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        user_folder = os.path.join(settings.MEDIA_ROOT, 'facial_data', instance.get_folder_name())

        if os.path.exists(user_folder):
            user_images = [f for f in os.listdir(user_folder) if f.endswith('.jpg') or f.endswith('.jpeg')]
        else:
            user_images = []

        if 'facial_data' in self.fields:
            if not user_images:
                representation['facial_data'] = 0
            else:
                request = self.context.get('request')
                representation['facial_data'] = request.build_absolute_uri(settings.MEDIA_URL + os.path.join('facial_data', instance.get_folder_name(), user_images[0]))

        for field in self.fields:
            if representation[field] is None:
                representation[field] = 0

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
