from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

class GoogleOAuthBackend(ModelBackend):
    def authenticate(self, request, email=None):
        UserModel = get_user_model()
        try:
            user = UserModel.objects.get(email=email)
            if user.check_password(email):  # This is not a typical use of check_password
                return user
        except UserModel.DoesNotExist:
            return None

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None