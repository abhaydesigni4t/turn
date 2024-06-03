from django.shortcuts import render,redirect,get_object_or_404
from django.contrib.auth import authenticate, login,logout
from .forms import LoginForm,NotificationForm,upload_form,YourModelForm,AssetForm,SiteForm,CompanyForm,timescheduleForm,TurnstileForm,OrientationForm,PreshitForm,ToolboxForm
from .models import CustomUser,UserEnrolled,Asset,Site,company,timeschedule,Notification,Upload_File,Turnstile_S,Orientation,PreShift,ToolBox
from .serializers import LoginSerializer,AssetSerializer,UserEnrolledSerializer,ExitSerializer,SiteSerializer,ActionStatusSerializer,NotificationSerializer,UploadedFileSerializer,TurnstileSerializer,facialDataSerializer,OrientationSerializer,signup_app,LoginSerializerApp,UserEnrolledSerializer1,AssetStatusSerializer,PreShiftSerializer,ToolBoxSerializer
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from django.views.generic.list import ListView
from django.views.generic import ListView
from django.views.generic.edit import CreateView
from django.views.generic.base import TemplateView
from django.views.generic import UpdateView,DeleteView,DetailView
from django.urls import reverse_lazy
from django.views import View
from django.http import JsonResponse,HttpResponse
from django.db import connection
from rest_framework.views import APIView
from django.core.cache import cache
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from rest_framework import generics
from .middleware import ActionStatusMiddleware
from django.core.exceptions import ValidationError
from rest_framework.parsers import MultiPartParser, FormParser
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import matplotlib.pyplot as plt
import os
from django.conf import settings
from django.db.models.functions import Lower



def user_login(request):            #extra
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)   
                return redirect('sites')
            else:             
                form.add_error(None, 'Invalid username or password')
    else:
        form = LoginForm()
    return render(request, 'app1/login.html', {'form': form})


def user_logout(request):    #extra
    logout(request)
    form = LoginForm()
    return render(request, 'app1/login.html', {'form': form})

@api_view(['POST'])
def check_data(request):
    username = request.data.get('username')
    password = request.data.get('password') 
    try:
        user = CustomUser.objects.get(username=username)
        if user.check_password(password):      
            return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
    except CustomUser.DoesNotExist:
        pass
    return Response({'message': 'Login failed'}, status=status.HTTP_401_UNAUTHORIZED)

class UserEnrolledListCreateView(ListCreateAPIView):
    queryset = UserEnrolled.objects.all()
    serializer_class = UserEnrolledSerializer

class UserEnrolledRetrieveUpdateDestroyView(RetrieveUpdateDestroyAPIView):
    queryset = UserEnrolled.objects.all()
    serializer_class = UserEnrolledSerializer

def post_notification(request):
    if request.method == 'POST':
        form = NotificationForm(request.POST)
        if form.is_valid():
            notification = form.save()
            return redirect('success')
    else:
        form = NotificationForm()
    return render(request, 'app1/notification.html', {'form': form})

def success_page(request):
    return render(request, 'app1/success.html')

def upload_file(request):
    if request.method == 'POST':
        form = upload_form(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return JsonResponse({'message': 'file saved successfully'})
    else:
        form = upload_form()
    return render(request, 'app1/upload.html', {'form': form})

def report_view(request):
    try:
        active_users = UserEnrolled.objects.filter(status='active').count()
        inactive_users = UserEnrolled.objects.filter(status='inactive').count()

        labels = ['Active', 'Inactive']
        sizes = [active_users, inactive_users]
        colors = ['#4CAF50', '#F44336'] 

        plt.figure(figsize=(6, 6))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
        #plt.title('User Status')
        plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

        chart_filename = 'pie_chart.png'
        chart_path = os.path.join(settings.MEDIA_ROOT, chart_filename)
        plt.savefig(chart_path)

        chart_url = os.path.join(settings.MEDIA_URL, chart_filename)
        return render(request, 'app1/report.html', {'chart_url': chart_url})
    except Exception as e:
        print(f"An error occurred: {e}")
        return render(request, 'app1/error.html', {'error_message': str(e)})

class get_data(ListView):
    model = UserEnrolled
    template_name = 'app1/getdata.html'
    context_object_name = 'data'
    paginate_by = 10  

    def get_queryset(self):
        return UserEnrolled.objects.all()

class create_data(CreateView):
    model = UserEnrolled 
    form_class = YourModelForm
    template_name = 'app1/add_user.html'
    success_url = reverse_lazy('get_all')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['data'] = UserEnrolled.objects.all()
        return context

class UpdateData(UpdateView):
    model = UserEnrolled 
    fields = '__all__'     
    template_name = 'app1/add_user.html'
    success_url = reverse_lazy('get_all')

class TaskDeleteView(DeleteView):
    model = UserEnrolled
    template_name = 'app1/data_confirm_delete.html'
    success_url = reverse_lazy('get_all')

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)    
                return redirect('sites')
            else:             
                form.add_error(None, 'Invalid username or password')
    else:
        form = LoginForm()
    return render(request, 'app1/app2_login.html', {'form': form})

def app2_logout(request):
    logout(request)
    return redirect('app2_login')

def management_view(request):
    return render(request,'app1/management.html')

def edit_worker(request):
    return render(request,'app1/worker_edit.html')

def asset_management(request):
    return render(request,'app1/asset_management.html')

def add_asset(request):
    if request.method == 'POST':
        form = AssetForm(request.POST,request.FILES)
        if form.is_valid():
            try:
                form.save()
                return redirect('asset_site')
            except ValidationError as e:
                form.add_error('asset_id', str(e))  
    else:
        form = AssetForm()
    return render(request, 'app1/add_asset.html', {'form': form})


def update_asset(request, asset_id):
    asset = get_object_or_404(Asset, asset_id=asset_id)
    
    if request.method == 'POST':
        form = AssetForm(request.POST, request.FILES, instance=asset)
        if form.is_valid():
            try:
                form.save()
                return redirect('asset_site')
            except ValidationError as e:
                form.add_error('asset_id', str(e))
    else:
        form = AssetForm(instance=asset)
    
    return render(request, 'app1/add_asset.html', {'form': form})

def asset_site(request):
    assets = Asset.objects.all()
    paginator = Paginator(assets, 8)

    page_number = request.GET.get('page')
    assets = paginator.get_page(page_number)

    return render(request, 'app1/asset_site.html', {'assets': assets})

def asset_details(request, asset_id):
    asset = get_object_or_404(Asset, asset_id=asset_id)
    return render(request, 'app1/view_asset.html', {'asset': asset})

class DownloadDatabaseView(APIView):
    def get(self, request, *args, **kwargs):  
        db_path = connection.settings_dict['NAME']
        with open(db_path, 'rb') as db_file:
            response = HttpResponse(db_file.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = 'attachment; filename=db.sqlite3'
            return response

def exit(request):
    assets = Asset.objects.filter(status='inactive')
    return render(request, 'app1/exit_status.html', {'assets': assets})

def site_view(request):
    sites = Site.objects.all()
    total_users = UserEnrolled.objects.count()
    active_users = UserEnrolled.objects.filter(status='active').count()
    inactive_users = UserEnrolled.objects.filter(status='inactive').count()
    print(f"Total Users: {total_users}, Active Users: {active_users}, Inactive Users: {inactive_users}")
    return render(request, 'app1/site.html', {
        'sites': sites,
        'total_users': total_users,
        'active_users': active_users,
        'inactive_users': inactive_users,
    })

def time_shedule(request):
    return render(request,'app1/time_shedule.html')

def setting_turn(request):
    turnstiles = Turnstile_S.objects.all()
    return render(request, 'app1/setting_turn.html', {'turnstiles': turnstiles})

class ActionStatusAPIView(APIView):
    def get(self, request, *args, **kwargs):
        status_data = {'status': 1 if ActionStatusMiddleware.perform_action() else 0}
        serializer = ActionStatusSerializer(status_data)
        return Response(serializer.data, status=status.HTTP_200_OK)

class ChangeDetectionView(APIView):
    def get(self, request, *args, **kwargs):
       
        has_changes = cache.get('has_changes', False)
        
        if has_changes:
            
            cache.set('has_changes', False)
            return Response({'changes_detected': 1})
        else:
            return Response({'changes_detected': 0})

@receiver(post_save, sender=UserEnrolled)
def book_change_handler(sender, instance, **kwargs):
 
    cache.set('has_changes', True)

@receiver(pre_delete, sender=UserEnrolled)
def book_delete_handler(sender, instance, **kwargs):
   
    cache.set('has_changes', True)

class LoginAPIView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(request, username=username, password=password)
            if user:
           
                token, created = Token.objects.get_or_create(user=user)
                return Response({'token': token.key, 'message': 'Login successful'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class AssetCreateAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = AssetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AssetListAPIView(generics.ListAPIView):
    queryset = Asset.objects.all()
    serializer_class = AssetSerializer

class UserEnrollListCreateAPIView(generics.ListCreateAPIView):
    queryset = UserEnrolled.objects.all()
    serializer_class = UserEnrolledSerializer

    def perform_create(self, serializer):
        serializer.save(orientation=self.request.data.get('orientation'))

class UserEnrollDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = UserEnrolled.objects.all()
    serializer_class = UserEnrolledSerializer

    def get_object(self):
        queryset = self.get_queryset()
        tag_id = self.kwargs.get('tag_id')  
        obj = generics.get_object_or_404(queryset, tag_id=tag_id) 
        return obj

class ExitListCreateAPIView(generics.ListCreateAPIView):
    queryset = Asset.objects.all()
    serializer_class = ExitSerializer

class ExitDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Asset.objects.all()
    serializer_class = ExitSerializer
    def get_object(self):
        queryset = self.get_queryset()
        asset_id = self.kwargs.get('asset_id')
        obj = generics.get_object_or_404(queryset, asset_id=asset_id)
        return obj

class SiteListAPIView(generics.ListAPIView):
    queryset = Site.objects.all()
    serializer_class = SiteSerializer

def add_site(request):
    if request.method == 'POST':
        form = SiteForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('sites') 
    else:
        form = SiteForm()
    return render(request, 'app1/add_site.html', {'form': form})

class SiteUpdateView(UpdateView):
    model = Site
    form_class = SiteForm
    template_name = 'app1/add_site.html'
    success_url = '/sites/'

    def get(self, request, *args, **kwargs):
        
        asset_instance = get_object_or_404(Site, pk=kwargs['pk'])
        
        form = self.form_class(instance=asset_instance)
        
        return self.render_to_response({'form': form})

class SiteDeleteView(DeleteView):
    model = Site
    template_name = 'app1/data_confirm_delete2.html'
    success_url = reverse_lazy('sites')

def company_view(request):
    compy = company.objects.all() 
    return render(request, 'app1/company.html', {'compy': compy})

def add_company_data(request):
    if request.method == 'POST':
        form = CompanyForm(request.POST,request.FILES)
        if form.is_valid():
            form.save()
            return redirect('company') 
    else:
        form = CompanyForm()
    return render(request, 'app1/add_company.html', {'form': form})

class CompanyUpdateView(UpdateView):
    model = company
    form_class = CompanyForm
    template_name = 'app1/add_company.html'
    success_url = '/company/'

    def get(self, request, *args, **kwargs):
        
        asset_instance = get_object_or_404(company, pk=kwargs['pk'])
        
        form = self.form_class(instance=asset_instance)
        
        return self.render_to_response({'form': form})

class CompanyDeleteView(DeleteView):
    model = company
    template_name = 'app1/data_confirm_delete3.html'
    success_url = reverse_lazy('company')

def timesche(request):
    data = timeschedule.objects.all()
    return render(request, 'app1/time_shedule.html', {'data': data})

class NotificationList(generics.ListAPIView):
    queryset = Notification.objects.all().order_by('-sr')
    serializer_class = NotificationSerializer

class FileUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        file_serializer = UploadedFileSerializer(data=request.data)
        if file_serializer.is_valid():
            file_serializer.save()
            return Response(file_serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(file_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
def add_timesh(request):
    if request.method == 'POST':
        form = timescheduleForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('time') 
    else:
        form = timescheduleForm()
    return render(request, 'app1/add_time.html', {'form': form})

def edit_timeschedule(request, id):
    instance = get_object_or_404(timeschedule, id=id)
    
    if request.method == 'POST':
        form = timescheduleForm(request.POST, instance=instance)
        if form.is_valid():
            form.save()
            return redirect('time')  
    else:
        form = timescheduleForm(instance=instance)

    return render(request, 'app1/add_time.html', {'form': form})

def delete_timeschedule(request, id):
    instance = get_object_or_404(timeschedule, id=id)
    if request.method == 'POST':
        instance.delete()
        return redirect('time')  
    return render(request, 'app1/data_confirm_delete6.html', {'instance': instance})

def add_turnstile(request):
    if request.method == 'POST':
        form = TurnstileForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('setting_t') 
    else:
        form = TurnstileForm()
    return render(request, 'app1/add_turnstile.html', {'form': form})

def delete_selected(request):
    if request.method == 'POST':
        selected_records = request.POST.getlist('selected_recordings')
        if 'select_all' in request.POST:
            selected_records = [str(record.pk) for record in Turnstile_S.objects.all()]
        Turnstile_S.objects.filter(pk__in=selected_records).delete()
        return redirect('setting_t')  
    return redirect('setting_t')

class TurnstileUpdateView(UpdateView):
    model = Turnstile_S
    form_class = TurnstileForm
    template_name = 'app1/add_turnstile.html' 
    success_url = reverse_lazy('setting_t')


class Turnstile_API(APIView):
    def get(self, request):
        turnstiles = Turnstile_S.objects.all()
        serializer = TurnstileSerializer(turnstiles, many=True)
        return Response(serializer.data)

def delete_selected1(request):
    if request.method == 'POST':
        selected_records = request.POST.getlist('selected_recordings')
        if 'select_all' in request.POST:
            selected_records = [str(record.pk) for record in Asset.objects.all()]
        Asset.objects.filter(pk__in=selected_records).delete()
        return redirect('exit')  
    return redirect('exit')

class Turnstile_get_single_api(generics.RetrieveAPIView):
    queryset = Turnstile_S.objects.all()
    serializer_class = TurnstileSerializer
    lookup_field = 'turnstile_id'
        
def delete_selected2(request):
    if request.method == 'POST':
        selected_records = request.POST.getlist('selected_recordings')
        if 'select_all' in request.POST:
            selected_records = [str(record.pk) for record in UserEnrolled.objects.all()]
        UserEnrolled.objects.filter(pk__in=selected_records).delete()
        return redirect('get_all')  
    return redirect('get_all')

def notification_view(request):
    noti_data =  Notification.objects.all() 
    return render(request, 'app1/notification1.html', {'noti_data': noti_data})

def orientation_task(request):
    if request.method == 'POST':
        form = OrientationForm(request.POST, request.FILES)  
        if form.is_valid():
            form.save()
            return render(request, 'app1/success1.html')
        else:
            print(form.errors)
    else:
        form = OrientationForm()
    latest_orientation = Orientation.objects.last()
 
    return render(request, 'app1/orientation.html', {'form': form, 'latest_orientation': latest_orientation})

def view_attachment(request, attachment_id):
    # Retrieve the attachment by ID (or any other identifier you use)
    orientation = Orientation.objects.get(id=attachment_id)
    # Assuming you have a 'attachments' field in your Orientation model
    attachment = orientation.attachments
    # Serve the attachment file
    response = HttpResponse(attachment, content_type='application/pdf')
    return response

class ChangeAssetStatus(APIView):
    def put(self, request, asset_id):
        try:
            asset = Asset.objects.get(asset_id=asset_id)
        except Asset.DoesNotExist:
            return Response({"error": "Asset not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = AssetStatusSerializer(asset, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def delete_selected3(request):
    if request.method == 'POST':
        selected_ids = request.POST.getlist('selected_records')
        if selected_ids:
            UserEnrolled.objects.filter(pk__in=selected_ids).delete()
        return redirect('get_all')  
    else:
        return render(request, 'app1/getdata.html', {'data': UserEnrolled.objects.all()})

def delete_selected4(request):
    if request.method == 'POST':
        selected_records = request.POST.getlist('selected_recordings')
        if 'select_all' in request.POST:
            selected_records = [str(record.pk) for record in Turnstile_S.objects.all()]
        Turnstile_S.objects.filter(pk__in=selected_records).delete()
        return redirect('setting_t')  
    return redirect('setting_t')

import json

def update_safety_confirmation(request):
    if request.method == 'POST' and request.is_ajax():
        data = json.loads(request.body)
        pk = data.get('pk')
        is_on = data.get('safety_confirmation')

        try:
            turnstile = Turnstile_S.objects.get(pk=pk)
            turnstile.safety_confirmation = is_on
            turnstile.save()
            return JsonResponse({'success': True})
        except Turnstile_S.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Turnstile not found'})
    else:
        return JsonResponse({'success': False, 'error': 'Invalid request'})
def sort_data(request):
   
    sort_by = request.GET.get('sort_by')
    sort_order = request.GET.get('sort_order')

    sortable_fields = {
        'sr': 'sr',
        'name': 'name',
        'company_name': 'company_name',
        'job_role': 'job_role',
        'mycompany_id': 'mycompany_id',
        'tag_id': 'tag_id',
        'job_location': 'job_location',
        'status': 'status'
       
    }

    data = UserEnrolled.objects.all()
    current_sort_order = request.session.get('sort_order', 'asc')
    if sort_by:
        current_sort_order = 'desc' if current_sort_order == 'asc' else 'asc'
    request.session['sort_order'] = current_sort_order

    for field_name, db_field_name in sortable_fields.items():
        if field_name == sort_by:
            lower_field_name = f'{db_field_name}_lower'
            data = data.annotate(**{lower_field_name: Lower(db_field_name)})
            break

    if sort_by:
        if current_sort_order == 'desc':
            data = data.order_by(f'-{lower_field_name}')
        else:
            data = data.order_by(lower_field_name)

    context = {
        'data': data,
        'sort_by': sort_by,
        'sort_order': current_sort_order
    }
    return render(request, 'app1/getdata.html', context)

def make_inactive_selected(request):
    if request.method == 'POST':
        selected_record_ids = request.POST.getlist('selected_recordings')

        UserEnrolled.objects.filter(pk__in=selected_record_ids).update(status='inactive')
    return redirect('get_all')

''' class FacialDataApi_extra(APIView):
    parser_classes = (MultiPartParser,)

    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get('email')
            facial_data = request.FILES.get('facial_data')

            if email:
                user_enrolled = UserEnrolled.objects.filter(email=email).first()

                if user_enrolled:
                    if facial_data:
                        user_enrolled.facial_data = facial_data
                        user_enrolled.save()
                    else:
                        return Response({'error': 'Facial data is required for update'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    if facial_data:
                        user_enrolled = UserEnrolled.objects.create(
                            email=email,
                            facial_data=facial_data
                        )
                    else:
                        return Response({'error': 'Facial data is required for new entry'}, status=status.HTTP_400_BAD_REQUEST)

                serializer = facialDataSerializer(user_enrolled)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Missing email parameter'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        '''
class OrientationListView(generics.ListAPIView):
    queryset = Orientation.objects.all()
    serializer_class = OrientationSerializer

class UpdateTagIDAPIView(APIView):
    def post(self, request, format=None):
        email = request.data.get('email')
        tag_id = request.data.get('tag_id')
        if email is not None and tag_id is not None:
            try:
                user = UserEnrolled.objects.get(email=email)
            except UserEnrolled.DoesNotExist:
                return Response({'error': 'User not found for the provided email.'}, status=status.HTTP_404_NOT_FOUND)
            serializer = UserEnrolledSerializer1(user, data={'tag_id': tag_id}, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'Tag ID updated successfully.'})
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'email and tag_id are required.'}, status=status.HTTP_400_BAD_REQUEST)

class UpdateOrientationAPIView(APIView):
    def post(self, request, format=None):
        email = request.data.get('email')
        orientation_file = request.FILES.get('orientation')
        
        if email is not None and orientation_file is not None:
            try:
                user = UserEnrolled.objects.get(email=email)
            except UserEnrolled.DoesNotExist:
                return Response({'error': 'User not found for the provided email.'}, status=status.HTTP_404_NOT_FOUND)
            
            user.orientation = orientation_file
            user.save()
            
            return Response({'message': 'Orientation file uploaded successfully.'})
        else:
            return Response({'error': 'Email and orientation file are required.'}, status=status.HTTP_400_BAD_REQUEST)
        

class LoginAPIApp(APIView):
    def post(self, request, format=None):
        serializer = LoginSerializerApp(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = UserEnrolled.objects.get(email=email)
            name = user.name
            return Response({'message': 'Login successful', 'name': name}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def signup_api_app(request):
    serializer = signup_app(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({"message": "Registration Successful"}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def site_document(request):
    return render(request,'app1/site_documents.html')

def preshift(request):
    documents = PreShift.objects.all()
    return render(request,'app1/preshift.html',{'documents' : documents})

def add_preshift(request):
    if request.method == 'POST':
        form = PreshitForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('preshift')
    else:
        form = PreshitForm()
    
    documents = PreShift.objects.all()
    return render(request, 'app1/add_preshift.html', {'form': form, 'documents': documents})

def edit_preshift(request, pk):
    preshift = get_object_or_404(PreShift, pk=pk)
    if request.method == 'POST':
        form = PreshitForm(request.POST, request.FILES, instance=preshift)
        if form.is_valid():
            form.save()
            return redirect('preshift')
    else:
        form = PreshitForm(instance=preshift)
    
    return render(request, 'app1/edit_preshift.html', {'form': form, 'preshift': preshift})

def delete_preshift(request, pk):
    preshift = get_object_or_404(PreShift, pk=pk)
    if request.method == 'POST':
        preshift.delete()
        return redirect('preshift')
    
    return render(request, 'app1/data_confirm_delete7.html', {'preshift': preshift})

def toolbox(request):
    documents = ToolBox.objects.all()
    return render(request,'app1/toolbox.html',{'documents' : documents})

def add_toolbox(request):
    if request.method == 'POST':
        form =ToolboxForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('toolbox')
    else:
        form = ToolboxForm()
    
    documents = ToolBox.objects.all()
    return render(request, 'app1/add_toolbox.html', {'form': form, 'documents': documents})

def edit_toolbox(request, pk):
    toolbox = get_object_or_404(ToolBox, pk=pk)
    if request.method == 'POST':
        form = ToolboxForm(request.POST, request.FILES, instance=toolbox)
        if form.is_valid():
            form.save()
            return redirect('toolbox')
    else:
        form = ToolboxForm(instance=toolbox)
    
    return render(request, 'app1/edit_toolbox.html', {'form': form, 'toolbox': toolbox})

def delete_toolbox(request, pk):
    toolbox = get_object_or_404(ToolBox, pk=pk)
    if request.method == 'POST':
        toolbox.delete()
        return redirect('toolbox')
    
    return render(request, 'app1/data_confirm_delete7.html', {'toolbox': toolbox})

class PreShiftListCreateAPIView(generics.ListCreateAPIView):
    queryset = PreShift.objects.all()
    serializer_class = PreShiftSerializer

class ToolBoxListCreateAPIView(generics.ListCreateAPIView):
    queryset = ToolBox.objects.all()
    serializer_class = ToolBoxSerializer


from .serializers import FacialImageDataSerializer

class FacialDataApi(APIView):
    def post(self, request):
        serializer = FacialImageDataSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            images = serializer.validated_data['facial_data']
            try:
                user = UserEnrolled.objects.get(email=email)
                for image in images:
                    user.facial_data = image
                    user.save()
                return Response("Images uploaded successfully", status=status.HTTP_200_OK)
            except UserEnrolled.DoesNotExist:
                return Response("User not found", status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


from .serializers import UserProfileSerializer

class UserProfileCreateAPIView(APIView):
    def post(self, request):
        serializer = UserProfileSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def show_facial_data_images(request, user_id):
    user = get_object_or_404(UserEnrolled, pk=user_id)
    user_folder = os.path.join('media', 'facial_data', user.get_folder_name())
    facial_data_images = []

    if os.path.exists(user_folder):
        for filename in os.listdir(user_folder):
            if filename.endswith(('.jpeg', '.jpg', '.png')):
                facial_data_images.append({
                    'url': os.path.join('/', user_folder, filename),
                    'filename': filename,
                    'user_id': user_id,
                })

    return render(request, 'app1/facial_data_images.html', {'facial_data_images': facial_data_images, 'user_id': user_id})

class OrientationCreateView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = OrientationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def view_attachment(request, attachment_id):
    orientation = Orientation.objects.get(id=attachment_id)
    attachment = orientation.attachments
    response = HttpResponse(attachment, content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename=' + attachment.name
    return response


from .serializers import UserComplySerializer

from rest_framework.parsers import MultiPartParser, FormParser

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import UserEnrolled
from .serializers import UserComplySerializer

class UserComplyAPIView(APIView):
    def post(self, request, format=None):
        email = request.data.get('email')
        my_comply_file = request.FILES.get('my_comply')
        if email is not None and my_comply_file is not None:
            try:
                user = UserEnrolled.objects.get(email=email)
            except UserEnrolled.DoesNotExist:
                return Response({'error': 'User not found for the provided email.'}, status=status.HTTP_404_NOT_FOUND)
            serializer = UserComplySerializer(instance=user, data={'my_comply': my_comply_file}, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'my_comply file uploaded successfully.'})
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Email and my_comply file are required.'}, status=status.HTTP_400_BAD_REQUEST)


def PreShiftfilterdata(request):
    selected_date = request.GET.get('selected_date')
    documents = PreShift.objects.all()

    if selected_date:
        documents = documents.filter(date=selected_date)

    return render(request, 'app1/preshift.html', {'documents': documents})

def toolboxfilterdata(request):
    selected_date = request.GET.get('selected_date')
    documents = ToolBox.objects.all()

    if selected_date:
        documents = documents.filter(date=selected_date)

    return render(request, 'app1/toolbox.html', {'documents': documents})


import os
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import UserEnrolled

def delete_facial_data_image(request, user_id, filename):
    user = get_object_or_404(UserEnrolled, pk=user_id)
    user_folder = os.path.join('media', 'facial_data', user.get_folder_name())
    file_path = os.path.join(user_folder, filename)

    if os.path.exists(file_path):
        os.remove(file_path)
        messages.success(request, 'Image deleted successfully.')
    else:
        messages.error(request, 'Image not found.')

    return redirect('show_facial_data_images', user_id=user_id)

from .forms import SingleFileUploadForm

def upload_facial_data_image(request, user_id):
    user = get_object_or_404(UserEnrolled, pk=user_id)
    user_folder = os.path.join('media', 'facial_data', user.get_folder_name())
    os.makedirs(user_folder, exist_ok=True)

    if request.method == 'POST':
        form = SingleFileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            image = request.FILES['facial_data']
            file_path = os.path.join(user_folder, image.name)
            with open(file_path, 'wb+') as destination:
                for chunk in image.chunks():
                    destination.write(chunk)
            messages.success(request, 'Image uploaded successfully.')
            return redirect('show_facial_data_images', user_id=user_id)
    else:
        form = SingleFileUploadForm()

    return render(request, 'app1/upload_facial_data_image.html', {
        'form': form,
        'user_id': user_id
    })

from .models import OnSiteUser

def onsite_user(request):
    user = OnSiteUser.objects.all()
    return render(request, 'app1/onsite_user.html', {'user': user})


def delete_selected5(request):
    if request.method == 'POST':
        selected_records = request.POST.getlist('selected_recordings')
        if 'select_all' in request.POST:
            selected_records = [str(record.pk) for record in OnSiteUser.objects.all()]
        OnSiteUser.objects.filter(pk__in=selected_records).delete()
        return redirect('onsite_user')  
    return redirect('onsite_user')


from rest_framework import generics
from .models import OnSiteUser
from .serializers import OnSiteUserSerializer

class OnSiteUserCreateView(generics.CreateAPIView):
    queryset = OnSiteUser.objects.all()
    serializer_class = OnSiteUserSerializer


from rest_framework import generics
from .models import OnSiteUser
from .serializers import OnsiteGetSerializer

class OnSiteUserListView(generics.ListAPIView):
    queryset = OnSiteUser.objects.all()
    serializer_class = OnsiteGetSerializer


class DeleteFacialDataImage(APIView):
    def delete(self, request, email, filename):
        # Get the user based on email
        user = get_object_or_404(UserEnrolled, email=email)
        user_folder = os.path.join(settings.MEDIA_ROOT, 'facial_data', user.name)

        # Construct the path to the image file
        file_path = os.path.join(user_folder, filename)

        # Check if the file exists
        if os.path.exists(file_path):
            # Delete the file
            os.remove(file_path)
            return Response("Image deleted successfully", status=status.HTTP_200_OK)
        else:
            return Response("Image not found", status=status.HTTP_404_NOT_FOUND)

import pickle

class FacialDataApi(APIView):
    def post(self, request):
        serializer = FacialImageDataSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            images = serializer.validated_data['facial_data']
            try:
                user = UserEnrolled.objects.get(email=email)
            except UserEnrolled.DoesNotExist:
                user = UserEnrolled.objects.create(email=email)

            user_folder = os.path.join(settings.MEDIA_ROOT, 'facial_data', str(user.name))
            if not os.path.exists(user_folder):
                os.makedirs(user_folder)

            existing_images = self.get_existing_images(user_folder)
            for image in images:
                # Use the original filename of each image
                image_name = image.name
                image_path = os.path.join(user_folder, image_name)
                with open(image_path, 'wb') as f:
                    for chunk in image.chunks():
                        f.write(chunk)

            # Train the facial recognition model and update pickle file
            self.update_pickle(user_folder)

            return Response("Images uploaded and facial data updated successfully", status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_existing_images(self, user_folder):
        # Return list of existing images in user's directory
        existing_images = []
        for file_name in os.listdir(user_folder):
            if file_name.endswith('.jpg'):
                existing_images.append(os.path.join(user_folder, file_name))
        return existing_images

    def update_pickle(self, user_folder):
        # Remove existing pickle file
        pickle_file_path = os.path.join(user_folder, 'encodings.pickle')
        if os.path.exists(pickle_file_path):
            os.remove(pickle_file_path)

        # Train the facial recognition model with all images in the directory
        encodings = self.train_facial_data(user_folder)

        # Save encodings to a new pickle file
        with open(pickle_file_path, 'wb') as f:
            pickle.dump(encodings, f)

    def train_facial_data(self, user_folder):
        encodings = []
        # Train facial data and get encodings for the user's images
        # Append the encodings to the encodings list
        return encodings