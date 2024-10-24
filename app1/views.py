
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
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_protect

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
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name
    
    if request.method == 'POST':
        form = NotificationForm(request.POST)
        if form.is_valid():
            notification = form.save()
            return redirect('notification1')
    else:
        form = NotificationForm()
    
    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/notification.html', {'form': form, 'site_name': site_name, 'site_names': site_names})


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

import matplotlib
matplotlib.use('Agg')  # Use a non-interactive backend
import matplotlib.pyplot as plt


def report_view(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]  # Create a tuple list for the dropdown

    try:
        active_users = UserEnrolled.objects.filter(status='active').count()
        inactive_users = UserEnrolled.objects.filter(status='inactive').count()
        pending_users = UserEnrolled.objects.filter(status='pending').count()
        total_users = active_users + inactive_users + pending_users

        labels = ['Active', 'Inactive', 'Pending']
        sizes = [active_users, inactive_users, pending_users]
        colors = ['#071390', '#5052cc', '#adaef0']

        plt.figure(figsize=(6, 6))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140, wedgeprops=dict(width=0.3))
        plt.text(0, 0, f'{total_users}', ha='center', va='center', fontsize=24)
        plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

        chart_filename = 'pie_chart.png'
        chart_path = os.path.join(settings.MEDIA_ROOT, chart_filename)
        plt.savefig(chart_path)
        plt.close()

        chart_url = os.path.join(settings.MEDIA_URL, chart_filename)
        return render(request, 'app1/report.html', {'chart_url': chart_url, 'site_name': site_name, 
                                                    'active_users': active_users, 'inactive_users': inactive_users,
                                                    'pending_users': pending_users, 'total_users': total_users,
                                                    'site_names': site_names })
    except Exception as e:
        return render(request, 'app1/error.html', {'error_message': str(e), 'site_name': site_name})
    
    
from django.db.models import IntegerField
from django.db.models.functions import Cast

class get_data(ListView):
    model = UserEnrolled
    template_name = 'app1/getdata.html'
    context_object_name = 'data'
    paginate_by = 3

    def get_queryset(self):
        queryset = UserEnrolled.objects.all()
        site_name = self.request.GET.get('site_name') or self.request.session.get('site_name')

        if site_name:
            queryset = queryset.filter(site__name=site_name)

        filter_name = self.request.GET.get('filterName', '')
        filter_company_name = self.request.GET.get('filterCompanyName', '')
        filter_job_role = self.request.GET.get('filterJobRole', '')
        filter_job_location = self.request.GET.get('filterJobLocation', '')
        filter_status = self.request.GET.get('filterStatus', '')

        if filter_name:
            queryset = queryset.filter(name__icontains=filter_name)
        if filter_company_name:
            queryset = queryset.filter(company_name__icontains=filter_company_name)
        if filter_job_role:
            queryset = queryset.filter(job_role__icontains=filter_job_role)
        if filter_job_location:
            queryset = queryset.filter(job_location__icontains=filter_job_location)
        if filter_status:
            queryset = queryset.filter(status=filter_status)
            
        sort_by = self.request.GET.get('sort_by')
        if sort_by:
            if sort_by == 'mycompany_id':
                queryset = queryset.order_by(Cast('mycompany_id', output_field=IntegerField()))
            elif sort_by == 'tag_id':
                queryset = queryset.order_by(Cast('tag_id', output_field=IntegerField()))
            elif sort_by == 'job_role':
                queryset = queryset.order_by('job_role')  # Sorting alphabetically
            elif sort_by == 'job_location':
                queryset = queryset.order_by('job_location')

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        site_name = self.request.GET.get('site_name') or self.request.session.get('site_name')
        if site_name:
            self.request.session['site_name'] = site_name  # Save site_name to session
        context['site_name'] = site_name

        # Filter sites based on user permissions
        user = self.request.user
        if user.is_staff and not user.is_superuser:
            # If the user is a sub-admin, get the sites associated with them
            sites = user.sites.all()
        else:
            # If the user is a super admin, get all sites
            sites = Site.objects.all()

        site_names = [(site.name, site.name) for site in sites]
        context['site_names'] = site_names

        context['filterName'] = self.request.GET.get('filterName', '')
        context['filterCompanyName'] = self.request.GET.get('filterCompanyName', '')
        context['filterJobRole'] = self.request.GET.get('filterJobRole', '')
        context['filterJobLocation'] = self.request.GET.get('filterJobLocation', '')
        context['filterStatus'] = self.request.GET.get('filterStatus', '')

        paginator = Paginator(self.get_queryset(), self.paginate_by)
        page = self.request.GET.get('page')
        page_obj = paginator.get_page(page)
        context['page_obj'] = page_obj
        context['paginator'] = paginator

        context['data'] = list(enumerate(page_obj.object_list, start=(page_obj.number - 1) * self.paginate_by + 1))
        return context

    
class create_data(CreateView):
    model = UserEnrolled
    form_class = YourModelForm
    template_name = 'app1/add_user.html'
    success_url = reverse_lazy('get_all')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        site_name = self.request.GET.get('site_name') or self.request.session.get('site_name')
        
        # Save site_name to session if it exists
        if site_name:
            self.request.session['site_name'] = site_name
        context['site_name'] = site_name
        
        # Filter sites based on user permissions
        user = self.request.user
        if user.is_staff and not user.is_superuser:
            # If the user is a sub-admin, get the sites associated with them
            sites = user.sites.all()
        else:
            # If the user is a super admin, get all sites
            sites = Site.objects.all()

        site_names = [(site.name, site.name) for site in sites]
        context['site_names'] = site_names

        context['data'] = UserEnrolled.objects.all()
        return context

class UpdateData(UpdateView):
    model = UserEnrolled 
    form_class = YourModelForm
    template_name = 'app1/add_user.html'
    success_url = reverse_lazy('get_all')

    def get_context_data(self, **kwargs):
        # Call the base implementation first to get a context
        context = super().get_context_data(**kwargs)

        # Handle site_name from request or session
        site_name = self.request.GET.get('site_name') or self.request.session.get('site_name')
        if site_name:
            self.request.session['site_name'] = site_name

        # Filter sites based on user permissions
        user = self.request.user
        if user.is_staff and not user.is_superuser:
            # If the user is a sub-admin, get the sites associated with them
            sites = user.sites.all()
        else:
            # If the user is a super admin, get all sites
            sites = Site.objects.all()

        site_names = [(site.name, site.name) for site in sites]

        # Add site_names and site_name to the context
        context['site_names'] = site_names
        context['site_name'] = site_name

        return context
    
    
class TaskDeleteView(DeleteView):
    model = UserEnrolled
    template_name = 'app1/data_confirm_delete.html'
    success_url = reverse_lazy('get_all')
    

@csrf_protect
def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password')
            user = authenticate(request, email=email, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, 'Login successful.')
                return redirect('sites')  # Change 'home' to your desired redirect page
            else:
                messages.error(request, 'Invalid email or password.')
    else:
        form = LoginForm()
    return render(request, 'app1/signup.html', {'form': form, 'is_login_page': True})

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
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    if request.method == 'POST':
        form = AssetForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                form.save()
                return redirect('asset_site')
            except ValidationError as e:
                form.add_error(None, str(e))  # Removed asset_id reference
    else:
        form = AssetForm()

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/add_asset.html', {'form': form, 'site_name': site_name, 'site_names': site_names})


def update_asset(request, id):
    asset = get_object_or_404(Asset, id=id)  # Use the default 'id' field instead of 'asset_id'

    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    if request.method == 'POST':
        form = AssetForm(request.POST, request.FILES, instance=asset)
        if form.is_valid():
            try:
                form.save()
                return redirect('asset_site')
            except ValidationError as e:
                form.add_error(None, str(e))  # Removed 'asset_id' reference
    else:
        form = AssetForm(instance=asset)

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/add_asset.html', {'form': form, 'site_name': site_name, 'site_names': site_names})


def delete_asset(request, id):
    asset = get_object_or_404(Asset, id=id)  # Use the default 'id' field instead of 'asset_id'
    
    if request.method == 'POST':
        asset.delete()
        messages.success(request, 'Asset deleted successfully.')
        return redirect('asset_site')
    
    return render(request, 'app1/data_confirm_delete9.html', {'asset': asset})


def asset_site(request):
    site_name = request.GET.get('site_name')
    if site_name:
        request.session['site_name'] = site_name
        try:
            site = Site.objects.get(name=site_name)
            assets = Asset.objects.filter(site=site)
        except Site.DoesNotExist:
            assets = Asset.objects.none()
    else:
        site_name = request.session.get('site_name')
        assets = Asset.objects.filter(site__name=site_name) if site_name else Asset.objects.all()

    paginator = Paginator(assets, 10)
    page_number = request.GET.get('page')
    assets = paginator.get_page(page_number)

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]

    return render(request, 'app1/asset_site.html', {'assets': assets, 'sites': sites, 'site_name': site_name,'site_names':site_names})


def asset_details(request, id):
    asset = get_object_or_404(Asset, id=id)  # Use the default 'id' field instead of 'asset_id'
    return render(request, 'app1/view_asset.html', {'asset': asset})


class DownloadDatabaseView(APIView):
    def get(self, request, *args, **kwargs):  
        db_path = connection.settings_dict['NAME']
        with open(db_path, 'rb') as db_file:
            response = HttpResponse(db_file.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = 'attachment; filename=db.sqlite3'
            return response

def exit(request):
    # Get the site_name from request GET parameters or session
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    
    if site_name:
        # Save the site_name in session
        request.session['site_name'] = site_name
        
        # Get the Site instance based on site_name
        site = get_object_or_404(Site, name=site_name)
        
        # Filter assets based on the Site instance
        assets = Asset.objects.filter(status='inactive', site=site)
    else:
        # Handle the case where site_name is not provided
        assets = Asset.objects.filter(status='inactive')

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    
    # Render the response with the filtered assets
    return render(request, 'app1/exit_status.html', {'assets': assets,'site_name':site_name,'site_names':site_names})


from django.db.models import Count, Q
from django.contrib.auth.decorators import login_required

@login_required
def site_view(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name
    user = request.user

    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.annotate(
            total_users=Count('userenrolled'),
            active_users=Count('userenrolled', filter=Q(userenrolled__status='active')),
            pending_users=Count('userenrolled', filter=Q(userenrolled__status='pending'))
        )
        site_names = [(site.name, site.name) for site in sites]
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.annotate(
            total_users=Count('userenrolled'),
            active_users=Count('userenrolled', filter=Q(userenrolled__status='active')),
            pending_users=Count('userenrolled', filter=Q(userenrolled__status='pending'))
        )
        sitess = Site.objects.all()
        site_names = [(site.name, site.name) for site in sitess]

    return render(request, 'app1/site.html', {
        'sites': sites,
        'site_name': site_name,
        'site_names': site_names
    })

    
def time_shedule(request):
    return render(request,'app1/time_shedule.html')


from .models import Turnstile_S, Site  # Assuming the correct model names

def setting_turn(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    queryset = Turnstile_S.objects.all()

    if site_name:
        try:
            site = Site.objects.get(name=site_name)
            queryset = queryset.filter(site=site)
            print(f"Site found: {site.name}")  # Debugging print statement
        except Site.DoesNotExist:
            queryset = Turnstile_S.objects.none()
            print(f"Site not found: {site_name}")  # Debugging print statement

    paginator = Paginator(queryset, 10)  # 10 items per page
    page_number = request.GET.get('page')
    turnstiles = paginator.get_page(page_number)

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/setting_turn.html', {'turnstiles': turnstiles, 'sites': sites, 'site_name': site_name,'site_names':site_names})


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
    parser_classes = (MultiPartParser, FormParser,)

    def post(self, request, *args, **kwargs):
        serializer = AssetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
from .serializers import UserProfileSerializer

class AssetListAPIView(generics.ListAPIView):
    queryset = Asset.objects.all()
    serializer_class = AssetSerializer
    
    
from django.http import JsonResponse
from .models import Asset, Site

def get_assets_by_site_name(request, site_name):
    normalized_site_name = site_name.lower()
    
    site = get_object_or_404(Site, name__iexact=normalized_site_name)
    
    assets = Asset.objects.filter(site=site)
    asset_data = []
    for asset in assets:
        asset_data.append({

            'picture': request.build_absolute_uri(asset.picture.url) if asset.picture else None,
            'asset_name': asset.asset_name,
            'tag_id': asset.tag_id,
            'footage': request.build_absolute_uri(asset.footage.url) if asset.footage else None,
            'description': asset.description,
            'status': asset.status,
            'location': asset.location,
            'time_log': asset.time_log.isoformat(),  # Or use any other format you prefer
            'site': site_name,
        })
    return JsonResponse({'assets': asset_data})


from django.core.files.storage import default_storage
from rest_framework import serializers

class UserEnrollListCreateAPIView(generics.ListCreateAPIView):
    queryset = UserEnrolled.objects.all()
    serializer_class = UserEnrolledSerializer

    def perform_create(self, serializer):
        email = self.request.data.get('email')
        if UserEnrolled.objects.filter(email=email).exists():
            raise serializers.ValidationError("This email already exists.")

        site_name = self.request.data.get('site', None)
        expiry_date = self.request.data.get('expiry_date', None)
        
        site_instance = None
        if site_name:
            site_instance = Site.objects.filter(name=site_name).first()
            if not site_instance:
                raise serializers.ValidationError("Site does not exist.")
        
        user_instance = serializer.save(site=site_instance)

        if expiry_date:
            user_instance.expiry_date = expiry_date
            user_instance.save()

        # Ensure the user folder exists
        user_folder = os.path.join(settings.MEDIA_ROOT, 'facial_data', user_instance.get_folder_name())
        os.makedirs(user_folder, exist_ok=True)

        # Move the picture to the correct folder if provided
        if 'picture' in self.request.FILES:
            picture_file = self.request.FILES['picture']
            picture_path = os.path.join(user_folder, picture_file.name)
            with open(picture_path, 'wb+') as destination:
                for chunk in picture_file.chunks():
                    destination.write(chunk)
            user_instance.picture = picture_path
            user_instance.save()

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context
    
class UserEnrollDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = UserEnrolled.objects.all()
    serializer_class = UserEnrolledSerializer

    def get_object(self):
        queryset = self.get_queryset()
        tag_id = self.kwargs.get('tag_id')  
        obj = generics.get_object_or_404(queryset, tag_id=tag_id) 
        return obj


class ExitListView(generics.ListAPIView):
    serializer_class = ExitSerializer

    def get_queryset(self):
        site_name = self.kwargs.get('site_name')
        
        # Filter assets by site and status 'inactive'
        if site_name:
            site = get_object_or_404(Site, name__iexact=site_name)
            return Asset.objects.filter(site=site, status='inactive')
        
        return Asset.objects.none()

class ExitCreateView(generics.CreateAPIView):
    serializer_class = ExitSerializer

    def perform_create(self, serializer):
        site_name = serializer.validated_data.get('site')
        
        if site_name:
            site = get_object_or_404(Site, name__iexact=site_name)
            # Create the exit status object with the site and set status to 'inactive'
            serializer.save(site=site, status='inactive')
        else:
            raise serializers.ValidationError({'site': ['Site name is required.']})
    
    
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
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name
    
    if request.method == 'POST':
        form = SiteForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('sites') 
    else:
        form = SiteForm()
    
    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/add_site.html', {'form': form, 'site_name': site_name, 'site_names': site_names})


class SiteUpdateView(UpdateView):
    model = Site
    form_class = SiteForm
    template_name = 'app1/add_site.html'
    success_url = '/sites/'

    def get(self, request, *args, **kwargs):
        asset_instance = get_object_or_404(Site, pk=kwargs['pk'])
        
        site_name = request.GET.get('site_name') or request.session.get('site_name')
        if site_name:
            request.session['site_name'] = site_name
        
        form = self.form_class(instance=asset_instance)
        
        # Filter sites based on user permissions
        user = request.user
        if user.is_staff and not user.is_superuser:
            # If the user is a sub-admin, get the sites associated with them
            sites = user.sites.all()
        else:
            # If the user is a super admin, get all sites
            sites = Site.objects.all()

        site_names = [(site.name, site.name) for site in sites]
        return self.render_to_response({'form': form, 'site_names': site_names,
            'site_name': site_name, })

class SiteDeleteView(DeleteView):
    model = Site
    template_name = 'app1/data_confirm_delete2.html'
    success_url = reverse_lazy('sites')

def company_view(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    compy = company.objects.all()

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]  # Create a tuple list for the dropdown
    return render(request, 'app1/company.html', {'compy': compy, 'site_name': site_name,'site_names':site_names})


def add_company_data(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    if request.method == 'POST':
        form = CompanyForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('company') 
    else:
        form = CompanyForm()
    
    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/add_company.html', {'form': form, 'site_name': site_name, 'site_names': site_names})


class CompanyUpdateView(UpdateView):
    model = company
    form_class = CompanyForm
    template_name = 'app1/add_company.html'
    success_url = '/company/'

    def get(self, request, *args, **kwargs):
        asset_instance = get_object_or_404(company, pk=kwargs['pk'])
        
        site_name = request.GET.get('site_name') or request.session.get('site_name')
        if site_name:
            request.session['site_name'] = site_name
        
        form = self.form_class(instance=asset_instance)
        
        # Filter sites based on user permissions
        user = request.user
        if user.is_staff and not user.is_superuser:
            # If the user is a sub-admin, get the sites associated with them
            sites = user.sites.all()
        else:
            # If the user is a super admin, get all sites
            sites = Site.objects.all()

        site_names = [(site.name, site.name) for site in sites]
        return self.render_to_response({'form': form, 'site_names': site_names,
            'site_name': site_name, })

class CompanyDeleteView(DeleteView):
    model = company
    template_name = 'app1/data_confirm_delete3.html'
    success_url = reverse_lazy('company')


from .models import timeschedule, Site  # Assuming the correct model names

def timesche(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    queryset = timeschedule.objects.all()

    if site_name:
        try:
            site = Site.objects.get(name=site_name)
            queryset = queryset.filter(site=site)
            print(f"Site found: {site.name}")  # Debugging print statement
        except Site.DoesNotExist:
            queryset = timeschedule.objects.none()
            print(f"Site not found: {site_name}")  # Debugging print statement

    paginator = Paginator(queryset, 10)  # 10 items per page
    page_number = request.GET.get('page')
    data = paginator.get_page(page_number)

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/time_shedule.html', {'data': data, 'sites': sites, 'site_name': site_name,'site_names':site_names})


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
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name
    
    if request.method == 'POST':
        form = timescheduleForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('time') 
    else:
        form = timescheduleForm()
    
    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/add_time.html', {'form': form, 'site_name': site_name, 'site_names': site_names})


def edit_timeschedule(request, id):
    instance = get_object_or_404(timeschedule, id=id)

    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    if request.method == 'POST':
        form = timescheduleForm(request.POST, instance=instance)
        if form.is_valid():
            form.save()
            return redirect('time')  
    else:
        form = timescheduleForm(instance=instance)

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/add_time.html', {'form': form,'site_name':site_name,'site_names':site_names})


def delete_timeschedule(request, id):
    instance = get_object_or_404(timeschedule, id=id)
    if request.method == 'POST':
        instance.delete()
        return redirect('time')  
    return render(request, 'app1/data_confirm_delete6.html', {'instance': instance})

def add_turnstile(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    if request.method == 'POST':
        form = TurnstileForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('setting_t') 
    else:
        form = TurnstileForm()
    
    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/add_turnstile.html', {'form': form, 'site_name': site_name, 'site_names': site_names})

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

    def get_context_data(self, **kwargs):
        # Call the base implementation first to get a context
        context = super().get_context_data(**kwargs)

        # Handle site_name from request or session
        site_name = self.request.GET.get('site_name') or self.request.session.get('site_name')
        if site_name:
            self.request.session['site_name'] = site_name

        # Filter sites based on user permissions
        user = self.request.user
        if user.is_staff and not user.is_superuser:
            # If the user is a sub-admin, get the sites associated with them
            sites = user.sites.all()
        else:
            # If the user is a super admin, get all sites
            sites = Site.objects.all()

        site_names = [(site.name, site.name) for site in sites]

        # Add site_names and site_name to the context
        context['site_names'] = site_names
        context['site_name'] = site_name

        return context


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
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    noti_data = Notification.objects.all()

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]  # Create a tuple list for the dropdown

    return render(request, 'app1/notification1.html', {'noti_data': noti_data, 'site_name': site_name,'site_names': site_names})

def orientation_task(request):
    # Retrieve site_name from GET parameters or session
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    success_message = None  # Initialize success message variable

    # Handle form submission
    if request.method == 'POST':
        form = OrientationForm(request.POST, request.FILES)
        if form.is_valid():
            orientation = form.save(commit=False)
            if site_name:
                site = Site.objects.filter(name=site_name).first()
                if site:
                    orientation.site = site
            orientation.save()
            success_message = "Document uploaded successfully!"  # Set success message
            form = OrientationForm()  # Reset form after successful submission
        else:
            print(form.errors)
    else:
        form = OrientationForm()

    # Fetch the latest orientation for the selected site
    latest_orientation = None
    if site_name:
        site = Site.objects.filter(name=site_name).first()
        if site:
            latest_orientation = Orientation.objects.filter(site=site).last()

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]

    return render(request, 'app1/orientation.html', {
        'form': form,
        'latest_orientation': latest_orientation,
        'site_name': site_name,
        'site_names': site_names,
        'success_message': success_message  # Pass success message to template
    })
    
def view_attachment(request, attachment_id):
    # Retrieve the attachment by ID (or any other identifier you use)
    orientation = get_object_or_404(Orientation, id=attachment_id)
    
    if orientation.attachments:
        # Serve the attachment file
        response = HttpResponse(orientation.attachments, content_type='application/pdf')
        return response
    else:
        return HttpResponse("Attachment not found", status=404)

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


from .serializers import GetOrientationSerializer

class GetOrientationApiView(APIView):
    def get(self, request, site_name):
        site = get_object_or_404(Site, name__iexact=site_name)
        orientations = Orientation.objects.filter(site=site)
        serializer = GetOrientationSerializer(orientations, many=True, context={'request': request})
        return Response(serializer.data)

class UpdateTagIDAPIView(APIView):
    def post(self, request, format=None):
        email = request.data.get('email')
        tag_id = request.data.get('tag_id')
        if email is not None and tag_id is not None:
            try:
                user = UserEnrolled.objects.get(email=email)
            except UserEnrolled.DoesNotExist:
                return Response({'error': 'User not found for the provided email.'}, status=status.HTTP_404_NOT_FOUND)
            
            # Check if the tag_id already exists
            if UserEnrolled.objects.filter(tag_id=tag_id).exists():
                return Response({'error': 'The provided tag ID already exists.'}, status=status.HTTP_400_BAD_REQUEST)
            
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
        


def site_document(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request,'app1/site_documents.html',{'site_name':site_name,'site_names':site_names})

from django.core.paginator import Paginator
from django.shortcuts import render
from datetime import datetime

from django.core.paginator import Paginator
from django.shortcuts import render
from datetime import datetime

def preshift(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    selected_date = request.GET.get('selected_date')  # Fetch selected date from GET parameters

    if site_name:
        request.session['site_name'] = site_name

    queryset = PreShift.objects.all()

    if site_name:
        try:
            site = Site.objects.get(name=site_name)
            queryset = queryset.filter(site=site)
        except Site.DoesNotExist:
            queryset = PreShift.objects.none()

    # If a date is selected, filter by that date
    if selected_date:
        try:
            date_obj = datetime.strptime(selected_date, '%Y-%m-%d').date()
            queryset = queryset.filter(date=date_obj)  # Use 'date' directly to filter the DateField
        except ValueError:
            pass  # Handle invalid date input if needed

    paginator = Paginator(queryset, 3)
    page_number = request.GET.get('page')
    preshifts = paginator.get_page(page_number)

    user = request.user
    if user.is_staff and not user.is_superuser:
        sites = user.sites.all()
    else:
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]

    return render(request, 'app1/preshift.html', {
        'preshifts': preshifts,
        'site_name': site_name,
        'site_names': site_names,
        'selected_date': selected_date  # Pass the selected date back to the template
    })


def add_preshift(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name
        
    if request.method == 'POST':
        form = PreshitForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('preshift')
    else:
        form = PreshitForm()
    
    documents = PreShift.objects.all()
    
    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/add_preshift.html', {'form': form, 'documents': documents,'site_name':site_name,'site_names':site_names})


def edit_preshift(request, pk):
    preshift = get_object_or_404(PreShift, pk=pk)
    
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name
    
    if request.method == 'POST':
        form = PreshitForm(request.POST, request.FILES, instance=preshift)
        if form.is_valid():
            form.save()
            return redirect('preshift')
    else:
        form = PreshitForm(instance=preshift)
    
    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/edit_preshift.html', {'form': form, 'preshift': preshift,'site_name':site_name,'site_names':site_names})


def delete_preshift(request, pk):
    preshift = get_object_or_404(PreShift, pk=pk)
    if request.method == 'POST':
        preshift.delete()
        return redirect('preshift')
    
    return render(request, 'app1/data_confirm_delete7.html', {'preshift': preshift})

def toolbox(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    selected_date = request.GET.get('selected_date')  # Get selected date from query parameters

    if site_name:
        request.session['site_name'] = site_name

    queryset = ToolBox.objects.all()

    if site_name:
        try:
            site = Site.objects.get(name=site_name)
            queryset = queryset.filter(site=site)
            print(f"Site found: {site.name}")  # Debugging print statement
        except Site.DoesNotExist:
            queryset = ToolBox.objects.none()
            print(f"Site not found: {site_name}")  # Debugging print statement

    if selected_date:
        # Filter by selected date (assuming 'date' is the correct field)
        queryset = queryset.filter(date=selected_date)  # Use the actual field name

    paginator = Paginator(queryset, 3)  # 3 items per page
    page_number = request.GET.get('page')
    toolbox_talks = paginator.get_page(page_number)

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]

    return render(request, 'app1/toolbox.html', {
        'toolbox_talks': toolbox_talks,
        'site_name': site_name,
        'selected_date': selected_date,  
        'site_names': site_names
    })


def add_toolbox(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    if request.method == 'POST':
        form = ToolboxForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('toolbox')
    else:
        form = ToolboxForm()

    documents = ToolBox.objects.all()

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/add_toolbox.html', {'form': form, 'documents': documents,'site_name':site_name,'site_names':site_names})


def edit_toolbox(request, pk):
    toolbox = get_object_or_404(ToolBox, pk=pk)

    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    if request.method == 'POST':
        form = ToolboxForm(request.POST, request.FILES, instance=toolbox)
        if form.is_valid():
            form.save()
            return redirect('toolbox')
    else:
        form = ToolboxForm(instance=toolbox)

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/edit_toolbox.html', {'form': form, 'toolbox': toolbox,'site_name':site_name,'site_names':site_names})


def delete_toolbox(request, pk):
    toolbox = get_object_or_404(ToolBox, pk=pk)
    if request.method == 'POST':
        toolbox.delete()
        return redirect('toolbox')
    
    return render(request, 'app1/data_confirm_delete7.html', {'toolbox': toolbox})

class PreShiftListCreateAPIView(generics.ListCreateAPIView):
    queryset = PreShift.objects.all()
    serializer_class = PreShiftSerializer

    def get_queryset(self):
        site_name = self.kwargs.get('site')
        if site_name:
            site = get_object_or_404(Site, name__iexact=site_name)
            return PreShift.objects.filter(site=site)
        else:
            return PreShift.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        site_name = serializer.validated_data.pop('site')
        site = Site.objects.get(name__iexact=site_name)
        serializer.save(site=site)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, headers=headers)

class ToolBoxListCreateAPIView(generics.ListCreateAPIView):
    queryset = ToolBox.objects.all()
    serializer_class = ToolBoxSerializer

    def get_queryset(self):
        site_name = self.kwargs.get('site')
        if site_name:
            site = get_object_or_404(Site, name__iexact=site_name)
            return ToolBox.objects.filter(site=site)
        else:
            return ToolBox.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        site_name = serializer.validated_data.pop('site')
        site = Site.objects.get(name__iexact=site_name)
        serializer.save(site=site)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, headers=headers)


from .serializers import UserProfileSerializer
from rest_framework.response import Response
from rest_framework import status

class UserProfileCreateAPIView(APIView):  
    def post(self, request):
        email = request.data.get('email')
        picture = request.data.get('picture')
        site_name = request.data.get('site', '')  # Get the site name if provided

        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        existing_user = UserEnrolled.objects.filter(email=email).first()
        if not existing_user:
            return Response({'error': 'User not found. Please sign up.'}, status=status.HTTP_404_NOT_FOUND)

        # Handle site lookup
        site = None
        if site_name:
            site = Site.objects.filter(name=site_name).first()
            if not site:
                return Response({'error': f'Site with name "{site_name}" not found.'}, status=status.HTTP_404_NOT_FOUND)
        else:
            # Set to first existing site if no site name is provided
            site = Site.objects.first()

        serializer = UserProfileSerializer(existing_user, data=request.data, partial=True)
        if serializer.is_valid():
            if picture:
                # Save picture to user's folder
                user_folder = os.path.join('media', 'facial_data', existing_user.get_folder_name())
                os.makedirs(user_folder, exist_ok=True)

                picture_name = picture.name
                picture_path = os.path.join(user_folder, picture_name)

                with open(picture_path, 'wb') as f:
                    for chunk in picture.chunks():
                        f.write(chunk)

                serializer.validated_data['picture'] = os.path.relpath(picture_path, 'media')

            if site:
                serializer.validated_data['site'] = site

            serializer.save()

            return Response(serializer.data, status=status.HTTP_200_OK)  # Status 200 for successful update

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
def show_facial_data_images(request, user_id):
    # Get site_name from GET parameters or session
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    # Retrieve the UserEnrolled object by user_id
    enrolled_user = get_object_or_404(UserEnrolled, pk=user_id)

    # Construct the user folder path for facial data
    user_folder = os.path.join('media', 'facial_data', enrolled_user.get_folder_name())
    facial_data_images = []

    # Check if the folder exists and retrieve the images
    if os.path.exists(user_folder):
        for filename in os.listdir(user_folder):
            if filename.endswith(('.jpeg', '.jpg', '.png')):
                facial_data_images.append({
                    'url': os.path.join('/', user_folder, filename),
                    'filename': filename,
                    'user_id': user_id,
                })

    # Prepare the list of site names for the dropdown
    site_names = [(site.name, site.name) for site in sites]

    # Render the template with facial data images and site names
    return render(request, 'app1/facial_data_images.html', {
        'facial_data_images': facial_data_images,
        'user_id': user_id,
        'site_names': site_names,
        'site_name': site_name,
    })


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
from django.views.decorators.csrf import csrf_exempt
from django.utils.dateparse import parse_date
from datetime import datetime

@csrf_exempt
def user_comply_api_view(request):
    if request.method == 'POST':
        # Use DRF parsers to handle multi-part form data
        request.parsers = [MultiPartParser, FormParser]

        # Extract form data and files
        data = request.POST.copy()  # Create a copy of POST data
        files = request.FILES  # Extract files from the request

        # Handle file uploads
        if 'my_comply' in files:
            data['my_comply'] = files['my_comply']

        # Initialize the serializer with the form data
        serializer = UserComplySerializer(data=data, context={'request': request})

        if serializer.is_valid():
            try:
                user = UserEnrolled.objects.get(email=serializer.validated_data['email'])
            except UserEnrolled.DoesNotExist:
                return JsonResponse({'error': 'User not found for the provided email.'}, status=status.HTTP_404_NOT_FOUND)
            
            user.my_comply = serializer.validated_data.get('my_comply', user.my_comply)
            user.mycompany_id = serializer.validated_data.get('mycompany_id', user.mycompany_id)
            user.expiry_date = serializer.validated_data.get('expiry_date', user.expiry_date)
            user.save()
            return JsonResponse({'message': 'my_comply file uploaded successfully.'}, status=status.HTTP_200_OK)
        else:
            return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        return JsonResponse({'error': 'Method not allowed.'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


    
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

        # Get all images in the user's facial_data folder after deletion
        user_images = [f for f in os.listdir(user_folder) if f.endswith('.jpg') or f.endswith('.jpeg')]

        # Check if there are images and the current picture is not in the user's folder
        if user_images and (not user.picture or os.path.basename(user.picture.name) not in user_images):
            # Find the next available image and set it as the user's picture
            for img_name in user_images:
                if not user.picture or img_name != os.path.basename(user.picture.name):
                    user.picture = os.path.join('facial_data', user.get_folder_name(), img_name)
                    user.save()
                    break

    else:
        messages.error(request, 'Image not found.')

    return redirect('show_facial_data_images', user_id=user_id)

from .forms import SingleFileUploadForm

def update_pickle(user_folder):
    pickle_file_path = os.path.join(user_folder, 'encodings.pickle')

    imagePaths = list(paths.list_images(user_folder))

    knownEncodings = []
    knownNames = []

    print(f"Total images found: {len(imagePaths)}")

    for (i, imagePath) in enumerate(imagePaths):
        print(f"--> processing image {i + 1}/{len(imagePaths)}")
        name = os.path.basename(os.path.dirname(imagePath))

        image = cv2.imread(imagePath)
        rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)

        boxes = face_recognition.face_locations(rgb, model="hog")
        encodings = face_recognition.face_encodings(rgb, boxes)

        print(f"Found {len(encodings)} face(s) in {imagePath}")

        for encoding in encodings:
            knownEncodings.append(encoding)
            knownNames.append(name)

    #print('--> encodings:', knownEncodings)
    # print('--> names:', knownNames)

    data = {"encodings": knownEncodings, "names": knownNames}
    with open(pickle_file_path, 'wb') as f:
        pickle.dump(data, f)

    print('--> encodings finalized')
 
import random
        
def upload_facial_data_image(request, user_id):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    # Prepare the list of site names for the dropdown
    site_names = [(site.name, site.name) for site in sites]
    
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
            update_pickle(user_folder)  # Update any relevant data or pickle files

            # Get all images in the user's facial_data folder
            user_images = [f for f in os.listdir(user_folder) if f.endswith('.jpg') or f.endswith('.jpeg')]

            # Debugging: Print the images found in the folder
            print(f"Images found in {user_folder}: {user_images}")

            # Set a random image as the user's picture
            if user_images:
                random_image = random.choice(user_images)
                user.picture = os.path.join('facial_data', user.get_folder_name(), random_image)
                user.save()

                # Debugging: Print the selected random image
                print(f"Selected random image for {user}: {random_image}")
            else:
                user.picture = None  # No image found, set picture to None or another default value
                user.save()

            messages.success(request, 'Image uploaded successfully.')
            return redirect('show_facial_data_images', user_id=user_id)
    else:
        form = SingleFileUploadForm()

    return render(request, 'app1/upload_facial_data_image.html', {
        'form': form,
        'user_id': user_id,
         'site_names': site_names,  # Add the site dropdown to the template context
        'site_name': site_name  # Pass the current selected site name
    })
    
from .models import OnSiteUser

def onsite_user(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    filter_name = request.GET.get('filterName', '').lower()
    filter_date = request.GET.get('filterDate', '')  

    if site_name:
        request.session['site_name'] = site_name

    queryset = OnSiteUser.objects.all()

    if site_name:
        try:
            site = Site.objects.get(name=site_name)
            queryset = queryset.filter(site=site)
        except Site.DoesNotExist:
            queryset = OnSiteUser.objects.none()

    # Apply name filter if provided
    if filter_name:
        queryset = queryset.filter(name__icontains=filter_name)

    # Apply date filter if provided and ensure correct format
    if filter_date:
        try:
            # Parse the date to ensure it's correct
            queryset = queryset.filter(timestamp__date=filter_date)
        except ValueError:
            pass  # Invalid date format, ignore

    paginator = Paginator(queryset, 3)
    page_number = request.GET.get('page')
    on_site_users = paginator.get_page(page_number)

    # Convert face field from boolean to 0/1
    for user in on_site_users:
        user.face = 1 if user.face else 0

    user = request.user
    if user.is_staff and not user.is_superuser:
        sites = user.sites.all()
    else:
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]

    return render(request, 'app1/onsite_user.html', {
        'on_site_users': on_site_users,
        'sites': sites,
        'site_name': site_name,
        'site_names': site_names,
        'filter_name': filter_name,
        'filter_date': filter_date,
    })


def delete_selected5(request):
    if request.method == 'POST':
        selected_records = request.POST.getlist('selected_recordings')
        if selected_records:
            OnSiteUser.objects.filter(pk__in=selected_records).delete()
        else:
            # Handle the case where no records are selected, maybe add a message or log
            pass
    return redirect('onsite_user')



from rest_framework import generics
from .models import OnSiteUser
from .serializers import OnSiteUserSerializer


# class OnSiteUserCreateAPIView(APIView):
#     def post(self, request):
#         serializer = OnSiteUserSerializer(data=request.data)
#         if serializer.is_valid():
#             site = serializer.validated_data.get('site')

#             # If site is None (not provided), default to the first site
#             if site is None:
#                 site = Site.objects.first()
#                 if site is None:
#                     return Response({"error": "No sites available."}, status=status.HTTP_400_BAD_REQUEST)
#                 # Update the validated_data with the default site
#                 serializer.validated_data['site'] = site

#             # Save the OnSiteUser instance with the site
#             serializer.save(site=site)
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         else:
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OnSiteUserCreateAPIView(APIView):
    def post(self, request):
        serializer = OnSiteUserSerializer(data=request.data)
        if serializer.is_valid():
            site = serializer.validated_data.get('site')

            # If site is None (not provided), default to the first site
            if site is None:
                site = Site.objects.first()
                if site is None:
                    return Response({"error": "No sites available."}, status=status.HTTP_400_BAD_REQUEST)
                # Update the validated_data with the default site
                serializer.validated_data['site'] = site

            # Save the OnSiteUser instance with the site and face fields
            serializer.save(site=site, face=serializer.validated_data['face'])
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from rest_framework import generics
from .models import OnSiteUser
from .serializers import OnsiteGetSerializer

class OnSiteUserListView(APIView):
    def get(self, request, site_name):
        site = get_object_or_404(Site, name__iexact=site_name)
        onsite_users = OnSiteUser.objects.filter(site=site)
        serializer = OnsiteGetSerializer(onsite_users, many=True)
        return Response(serializer.data)


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


# from imutils import paths
# import face_recognition
# import pickle
# import cv2
# from .serializers import FacialImageDataSerializer

# class FacialDataApi(APIView):
#     def post(self, request):
#         serializer = FacialImageDataSerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']
#             images = serializer.validated_data['facial_data']
#             try:
#                 user = UserEnrolled.objects.get(email=email)
#                 for image in images:
#                     user.facial_data = image
#                     user.save()
                    
#                 if images:
#                     random_image = random.choice(images)
#                     user.picture = random_image
#                     user.save()
                    
#             except UserEnrolled.DoesNotExist:
#                 return Response("User not found", status=status.HTTP_404_NOT_FOUND)
#             user_folder = os.path.join(settings.MEDIA_ROOT, 'facial_data', str(user.name))
#             self.update_pickle(user_folder)

#             return Response("Images uploaded and facial data updated successfully", status=status.HTTP_200_OK)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def update_pickle(self, user_folder):
#         pickle_file_path = os.path.join(user_folder, 'encodings.pickle')

#         imagePaths = list(paths.list_images(user_folder))

#         knownEncodings = []
#         knownNames = []

#         print(f"Total images found: {len(imagePaths)}")

#         for (i, imagePath) in enumerate(imagePaths):
#             print(f"--> processing image {i + 1}/{len(imagePaths)}")
#             name = os.path.basename(os.path.dirname(imagePath))

#             image = cv2.imread(imagePath)
#             rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)

#             boxes = face_recognition.face_locations(rgb, model="hog")
#             encodings = face_recognition.face_encodings(rgb, boxes)

#             print(f"Found {len(encodings)} face(s) in {imagePath}")

#             for encoding in encodings:
#                 knownEncodings.append(encoding)
#                 knownNames.append(name)

#         #print('--> encodings:', knownEncodings)
#         # print('--> names:', knownNames)

#         data = {"encodings": knownEncodings, "names": knownNames}
#         with open(pickle_file_path, 'wb') as f:
#             pickle.dump(data, f)

#         print('--> encodings finalized') 



import os
import random
from imutils import paths
import face_recognition
import pickle
import cv2
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from .serializers import FacialImageDataSerializer
from .models import UserEnrolled

class FacialDataApi(APIView):
    def post(self, request):
        serializer = FacialImageDataSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            images = serializer.validated_data['facial_data']
            try:
                user = UserEnrolled.objects.get(email=email)

                # Create user folder if it doesn't exist
                user_folder = os.path.join(settings.MEDIA_ROOT, 'facial_data', str(user.name))
                os.makedirs(user_folder, exist_ok=True)

                # Save images to the user's folder
                for image in images:
                    image_name = f"{user.name}_{random.randint(1000, 9999)}.jpg"  # Random name to avoid conflicts
                    image_path = os.path.join(user_folder, image_name)
                    with open(image_path, 'wb') as f:
                        f.write(image.read())  # Save the image data to a file

                # Randomly select an image for the user's picture
                if images:
                    random_image = random.choice(images)
                    user.picture = random_image
                    user.save()

            except UserEnrolled.DoesNotExist:
                return Response("User not found", status=status.HTTP_404_NOT_FOUND)

            # Update encodings pickle file
            self.update_pickle(user_folder)

            return Response("Images uploaded and facial data updated successfully", status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update_pickle(self, user_folder):
        pickle_file_path = os.path.join(user_folder, 'encodings.pickle')

        imagePaths = list(paths.list_images(user_folder))

        knownEncodings = []
        knownNames = []

        print(f"Total images found: {len(imagePaths)}")

        for (i, imagePath) in enumerate(imagePaths):
            print(f"--> processing image {i + 1}/{len(imagePaths)}")
            name = os.path.basename(os.path.dirname(imagePath))

            image = cv2.imread(imagePath)
            rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)

            boxes = face_recognition.face_locations(rgb, model="hog")
            encodings = face_recognition.face_encodings(rgb, boxes)

            print(f"Found {len(encodings)} face(s) in {imagePath}")

            for encoding in encodings:
                knownEncodings.append(encoding)
                knownNames.append(name)

        data = {"encodings": knownEncodings, "names": knownNames}
        with open(pickle_file_path, 'wb') as f:
            pickle.dump(data, f)

        print('--> encodings finalized')


        
'''     
class FacialDataApi_extra(APIView):
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
    
'''
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
    
    '''

import os
import pickle

def load_encodings_from_dir(directory):
    stored_data_encodings = []
    stored_data_names = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file == 'encodings.pickle':
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    pickleData = pickle.load(f)
                    stored_data_encodings.extend(pickleData.get('encodings'))
                    stored_data_names.extend(pickleData.get('names'))
    data = {"encodings": stored_data_encodings, "names": stored_data_names}
    combined_file_path = os.path.join("media", "combined.pickle")
    with open(combined_file_path, "wb") as f:
        f.write(pickle.dumps(data))
    print('--> encodings combined')

from django.http import FileResponse
import os

class DownloadCombinedFile(APIView):
    def get(self, request):
        faacialDataPath = os.path.join("media", "facial_data")
        load_encodings_from_dir(faacialDataPath)
        combined_file_path = os.path.join("media", "combined.pickle")
        if os.path.exists(combined_file_path):
            return FileResponse(open(combined_file_path, 'rb'), as_attachment=True)
        else:
            return Response({"error": "Combined file does not exist"}, status=status.HTTP_404_NOT_FOUND)
        


class UserNameByTagIdAPIView(APIView):
    def post(self, request):
        tag_id = request.data.get('tag_id')
        if tag_id is not None:
            try:
                user = UserEnrolled.objects.get(tag_id=tag_id)
                return Response({'name': user.name}, status=status.HTTP_200_OK)
            except UserEnrolled.DoesNotExist:
                return Response({'error': 'User not found for the provided tag_id'}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'error': 'tag_id is required'}, status=status.HTTP_400_BAD_REQUEST)

from .serializers import PostSiteSerializer

class SiteCreateAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = PostSiteSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SiteDeleteByNameAPIView(APIView):
    def delete(self, request, *args, **kwargs):
        name = request.data.get('name', None)
        if name is not None:
            try:
                site = Site.objects.get(name__iexact=name)
                site.delete()
                
                return Response({'message': 'Site deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
            except Site.DoesNotExist:
                return Response({'error': 'Site not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'error': 'Name parameter not provided'}, status=status.HTTP_400_BAD_REQUEST)
    


class UserEnrolledStatusCountView(APIView):
    def get(self, request):
        sites = Site.objects.all()
        site_data = []

        for site in sites:
            # Count total users, active users, and inactive users for the site
            total_users = UserEnrolled.objects.filter(site=site).count()
            active_users = UserEnrolled.objects.filter(site=site, status='active').count()
            inactive_users = UserEnrolled.objects.filter(site=site, status='inactive').count()
            
            site_dict = {
                'picture_url': request.build_absolute_uri(site.picture.url) if site.picture else None,
                'name': site.name,
                'location': site.location,
                'total_users': total_users,
                'active_users': active_users,
                'inactive_users': inactive_users,
            }
            site_data.append(site_dict)
        
        return Response(site_data, status=status.HTTP_200_OK)
    
from .serializers import EmailSerializer

class UserImageView(APIView):
    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = UserEnrolled.objects.get(email=email)
                # Check if the user has a picture and if the picture file exists
                if user.picture and os.path.exists(user.picture.path):
                    image_url = user.picture.url
                    return Response({"image_url": image_url}, status=status.HTTP_200_OK)
                else:
                    # Find any image in the user's folder if the picture field is empty or file does not exist
                    user_folder = os.path.join(settings.MEDIA_ROOT, 'facial_data', str(user.get_folder_name()))
                    if os.path.exists(user_folder):
                        user_images = [f for f in os.listdir(user_folder) if f.endswith('.jpg') or f.endswith('.jpeg')]
                        if user_images:
                            random_image = random.choice(user_images)
                            image_url = os.path.join(settings.MEDIA_URL, 'facial_data', user.get_folder_name(), random_image)
                            return Response({"image_url": image_url}, status=status.HTTP_200_OK)
                    return Response({"error": "No image found"}, status=status.HTTP_404_NOT_FOUND)
            except UserEnrolled.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    

from .serializers import GetUserEnrolledSerializer

@api_view(['POST'])
def get_user_data(request):
    email = request.data.get('email')
    if not email:
        return Response({"error": "Email parameter is required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = UserEnrolled.objects.get(email=email)

        # Debugging: Print user folder path
        user_folder = os.path.join('media', 'facial_data', user.get_folder_name())
        print(f"User folder path: {user_folder}")

        serializer = GetUserEnrolledSerializer(user, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)
    except UserEnrolled.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    
    
from django.contrib.auth import login
from .forms import SignUpForm

@csrf_protect
def signup_view(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Signup successful. Please log in.')
            return redirect('signup')  # Redirect to login page after successful signup
    else:
        form = SignUpForm()
    return render(request, 'app1/signup.html', {'form': form, 'is_signup_page': True})



from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .serializers import UserEnrolledSerializer11, UserEnrolledUpdateSerializer11
from .models import UserEnrolled



class UserEnrolledUpdateView11(APIView):
    def put(self, request, format=None):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = UserEnrolled.objects.get(email=email)
        except UserEnrolled.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = UserEnrolledUpdateSerializer11(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetUserByEmailView(APIView):
    def post(self, request, format=None):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = UserEnrolled.objects.get(email=email)
        except UserEnrolled.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = UserEnrolledSerializer11(user)
        user_data = serializer.data
        user_data.pop('password', None)  # Remove the password from the serialized data
        return Response(user_data, status=status.HTTP_200_OK)

from .serializers import SignUpSerializer

class SignUpView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = SignUpSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "created successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

from .serializers import AdminLoginSerializer

class AdminLoginView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = AdminLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            return Response({"message": "Login successful.", "user_name": user.name}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def test50(request):
    return render(request,'app1/test50.html')


from .serializers import SignupSerializer_new,LoginSerializer_new,UserSerializer_new

class SignupView_new(APIView):
    def post(self, request, format=None):
        serializer = SignupSerializer_new(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView_new(APIView):
    def post(self, request, format=None):
        serializer = LoginSerializer_new(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)

from .forms import SignUpForm_new
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def signup_view_new(request):
    if request.method == 'POST':
        form = SignUpForm_new(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            messages.success(request, 'Signup successful. Please log in.')
            return redirect('login')  # Redirect to login page after successful signup
    else:
        form = SignUpForm_new()
    return render(request, 'app1/signup.html', {'form': form, 'is_signup_page': True})


from .forms import LoginForm_new

@csrf_protect
def login_view_new(request):
    if request.method == 'POST':
        form = LoginForm_new(request.POST)
        if form.is_valid():
            # Convert email to lowercase before authentication
            email = form.cleaned_data.get('email').lower()
            password = form.cleaned_data.get('password')
            user = authenticate(request, email=email, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, 'Login successful.')
                return redirect('sites')
            else:
                messages.error(request, 'Invalid email or password.')
    else:
        form = LoginForm_new()
    return render(request, 'app1/signup.html', {'form': form, 'is_login_page': True})

import re

@api_view(['POST'])
def signup_api_app(request):
    email = request.data.get('email', '')
    
    # Check if the email already exists
    if UserEnrolled.objects.filter(email=email).exists():
        return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)
    
    # Email format validation using regex
    pat = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    if not re.match(pat, email):
        return Response({"error": "Invalid Email format"}, status=status.HTTP_400_BAD_REQUEST)

    serializer = signup_app(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({"message": "Registration Successful"}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIApp(APIView):
    def post(self, request, format=None):
        serializer = LoginSerializerApp(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = UserEnrolled.objects.get(email=email)
            name = user.name
            return Response({'message': 'Login successful', 'name': name}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializerApp1
class LoginAPIApp1(APIView):
    def post(self, request, format=None):
        serializer = LoginSerializerApp1(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = UserEnrolled.objects.get(email=email)
            name = user.name
            
            # Generate JWT token
            refresh = RefreshToken.for_user(user)
            token = refresh.access_token
            
            response_data = {
                'message': 'Login successful',
                'name': name,
                'access_token': str(token),
                'refresh_token': str(refresh),
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import SignupUserRetrieveSerializer,SignupUserUpdateSerializer
from django.contrib.auth import get_user_model

class GetSignupUserRetrieveAPIView(APIView):
    def get(self, request, email):
        try:
            user = get_object_or_404(get_user_model(), email=email)
            serializer = SignupUserRetrieveSerializer(user)
            return Response(serializer.data)
        except get_user_model().DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    
    
class SignupUserUpdateView(APIView):
    def patch(self, request, email):
        try:
            user = get_object_or_404(get_user_model(), email=email)
            serializer = SignupUserUpdateSerializer(instance=user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except get_user_model().DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
   
from .serializers import UserEnrolledSerializerExpiry
     
    
    
class ExpiryPostAPIView(APIView):
    def post(self, request, format=None):
        serializer = UserEnrolledSerializerExpiry(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['email']
            user.name = serializer.validated_data.get('name', user.name)
            user.my_comply = serializer.validated_data.get('my_comply', user.my_comply)
            user.expiry_date = serializer.validated_data.get('expiry_date', user.expiry_date)
            user.save()
            return Response({'message': 'User updated successfully.'}, status=200)
        return Response(serializer.errors, status=400)
    

    
from django.views.decorators.csrf import csrf_exempt
from rest_framework import generics, permissions, status
from django.core.files import File


'''
from rest_framework.parsers import MultiPartParser, FormParser

class update_user_api(APIView):
    parser_classes = (MultiPartParser, FormParser,)

    def put(self, request, *args, **kwargs):
        return self.update_user(request)

    def patch(self, request, *args, **kwargs):
        return self.update_user(request, partial=True)

    def update_user(self, request, partial=False):
        email = request.data.get('email')
        if not email:
            return Response({"detail": "Email parameter is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_enrolled = UserEnrolled.objects.get(email=email)
        except UserEnrolled.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        # Handle site name
        site_name = request.data.get('site')
        if site_name:
            try:
                site = Site.objects.get(name=site_name.upper())
                request.data['site'] = site.id
            except Site.DoesNotExist:
                return Response({"detail": "Site with the given name does not exist."}, status=status.HTTP_400_BAD_REQUEST)

        # Use the serializer to validate and update data
        serializer = UpdateEnrolledSerializer(user_enrolled, data=request.data, partial=partial)
        if serializer.is_valid():
            updated_fields = self.perform_update(serializer, request, user_enrolled)
            response_data = {field: serializer.data.get(field) for field in updated_fields}
            response_data = self.add_full_image_urls(response_data, user_enrolled)
            return Response(response_data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def perform_update(self, serializer, request, user_enrolled):
        # Save the instance while keeping the password unchanged
        instance = serializer.instance
        password = instance.password
        serializer.save(password=password)

        # Ensure the user's folder exists
        user_folder = os.path.join(settings.MEDIA_ROOT, 'user_pictures', user_enrolled.get_folder_name())
        os.makedirs(user_folder, exist_ok=True)

        # Update file fields if present in request.FILES
        for field_name in ['orientation', 'facial_data', 'my_comply']:
            if field_name in request.FILES:
                file = request.FILES[field_name]
                file_path = os.path.join(user_folder, file.name)
                with open(file_path, 'wb+') as destination:
                    for chunk in file.chunks():
                        destination.write(chunk)
                setattr(instance, field_name, file_path)
            elif field_name not in request.data:  # Handle case where field is not in request at all
                setattr(instance, field_name, None)

        instance.save()

        # Get the list of updated fields
        return serializer.validated_data.keys()

    def add_full_image_urls(self, data, instance):
        # Add full URLs for image fields
        request = self.request
        if 'picture' in data:
            data['picture'] = request.build_absolute_uri(instance.picture.url)
        if 'orientation' in data:
            data['orientation'] = request.build_absolute_uri(instance.orientation.url) if instance.orientation else None
        if 'facial_data' in data:
            data['facial_data'] = request.build_absolute_uri(instance.facial_data.url) if instance.facial_data else None
        if 'my_comply' in data:
            data['my_comply'] = request.build_absolute_uri(instance.my_comply.url) if instance.my_comply else None

        # Add site name to the response
        if instance.site:
            data['site'] = instance.site.name

        return data
'''
    
@csrf_exempt
def delete_user_api(request):
    if request.method == 'DELETE':
        data = json.loads(request.body)
        email = data.get('email')
        
        # Check if email is provided
        if not email:
            return JsonResponse({'error': 'Email is required to delete a user.'}, status=400)
        
        try:
            user = UserEnrolled.objects.get(email=email)
        except UserEnrolled.DoesNotExist:
            return JsonResponse({'error': 'User with the provided email does not exist.'}, status=404)
        
        user.delete()
        return JsonResponse({'message': 'User deleted successfully'}, status=200)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


from .serializers import BulkUpdateByEmailSerializer
from rest_framework import status, views

class BulkUpdateByEmailView(views.APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        serializer = BulkUpdateByEmailSerializer(data=data, many=True)

        if serializer.is_valid():
            updates = serializer.validated_data
            update_count = 0

            for update in updates:
                email = update['email']
                status_update = update['status']

                # Update status for the user with the given email
                updated_rows = UserEnrolled.objects.filter(email=email).update(status=status_update)
                update_count += updated_rows

            return Response({'status': 'success', 'updated_count': update_count}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .forms import SubAdminCreationForm

@login_required
def create_subadmin(request):
    site_name = request.GET.get('site_name') or request.session.get('site_name')
    if site_name:
        request.session['site_name'] = site_name
        
    success_message = None  # Initialize success message variable

    if request.method == 'POST':
        form = SubAdminCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_staff = True
            user.is_superuser = False
            user.set_password(form.cleaned_data['password'])
            user.save()
            sites = form.cleaned_data['sites']
            user.sites.set(sites)
            success_message = "Subadmin created successfully!"  # Set success message
            form = SubAdminCreationForm()  # Reset form after successful submission
        else:
            # Return form errors with the form
            return render(request, 'app1/create_subadmin.html', {'form': form, 'errors': form.errors})

    else:
        form = SubAdminCreationForm()

    # Filter sites based on user permissions
    user = request.user
    if user.is_staff and not user.is_superuser:
        # If the user is a sub-admin, get the sites associated with them
        sites = user.sites.all()
    else:
        # If the user is a super admin, get all sites
        sites = Site.objects.all()

    site_names = [(site.name, site.name) for site in sites]
    return render(request, 'app1/create_subadmin.html', {
        'form': form,
        'success_message': success_message,  # Pass success message to template
        'site_name':site_name,
        'site_names':site_names,
    })

@login_required
def subadmin_success(request):
    return render(request, 'app1/subadmin_success.html')


from django.contrib.auth.mixins import UserPassesTestMixin

class SitePermissionMixin:
    def get_queryset(self):
        queryset = super().get_queryset()
        user_sites = self.request.user.sites.all()
        permitted_site_names = [site.name for site in user_sites]
        return queryset.filter(site__name__in=permitted_site_names)

from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
  
'''

class create_data(LoginRequiredMixin, SitePermissionMixin, CreateView):
    model = UserEnrolled
    form_class = YourModelForm
    template_name = 'app1/add_user.html'
    success_url = reverse_lazy('get_all')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['data'] = UserEnrolled.objects.all()
        return context

class UpdateData(LoginRequiredMixin, SitePermissionMixin, UpdateView):
    model = UserEnrolled
    fields = ['name', 'company_name', 'job_role', 'mycompany_id', 'tag_id', 'job_location', 'orientation', 'facial_data', 'my_comply', 'expiry_date', 'status', 'email', 'site']
    template_name = 'app1/add_user.html'
    success_url = reverse_lazy('get_all')

class TaskDeleteView(LoginRequiredMixin, SitePermissionMixin, DeleteView):
    model = UserEnrolled
    template_name = 'app1/data_confirm_delete.html'
    success_url = reverse_lazy('get_all')
    
    
    '''

from . serializers import UserEnrolledSerializer_update

class UserEnrolledUpdateAPIView_n(generics.UpdateAPIView):
    queryset = UserEnrolled.objects.all()
    serializer_class = UserEnrolledSerializer_update

    def get_object(self):
        email = self.request.data.get('email')
        if email is None:
            raise serializers.ValidationError("Email parameter is required for update.")
        return get_object_or_404(UserEnrolled, email=email)

    def update(self, request, *args, **kwargs):
        # Get the original instance
        instance = self.get_object()
        original_data = self.get_serializer(instance).data

        # Ensure that the password field is not updated
        data = request.data.copy()
        if 'password' in data:
            data.pop('password')

        # Validate and retrieve the site if provided
        site_name = data.get('site', None)
        if site_name:
            try:
                site = Site.objects.get(name=site_name)
                data['site'] = site.pk  # Store the primary key instead of the entire object
            except Site.DoesNotExist:
                return Response({"error": "The specified site does not exist."}, status=status.HTTP_400_BAD_REQUEST)

        # Create the serializer with the updated data
        serializer = self.get_serializer(instance, data=data, partial=True)
        serializer.is_valid(raise_exception=True)

        # Save the instance
        self.perform_update(serializer)

        # Get the updated data
        updated_data = serializer.data

        # Construct a response containing only the changed fields
        changed_fields = {field: updated_data[field] for field in updated_data if updated_data[field] != original_data[field]}
        
        # Ensure site_name is included in the response
        if 'site' in changed_fields:
            changed_fields['site'] = site_name

        # Return the response with only the updated fields
        return Response(changed_fields)

    def perform_update(self, serializer):
        serializer.save(password=self.get_object().password)  # Keep the original password
        


from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import Turnstile_S
from .serializers import TurnstileUnlockSerializer

@api_view(['POST'])
def turnstile_status(request):
    # Extract turnstile_id from form data
    turnstile_id = request.data.get('turnstile_id')

    if not turnstile_id:
        return Response({'error': 'turnstile_id form data is required'}, status=400)

    try:
        # Ensure turnstile_id is an integer
        turnstile_id = int(turnstile_id)
        turnstile = Turnstile_S.objects.get(turnstile_id=turnstile_id)
    except ValueError:
        return Response({'error': 'Invalid turnstile_id format'}, status=400)
    except Turnstile_S.DoesNotExist:
        return Response({'error': 'Turnstile not found'}, status=404)

    serializer = TurnstileUnlockSerializer(turnstile)
    return Response(serializer.data)



from .models import UpdateStatus

class DatasetUpdateStatusView(APIView):
    def get(self, request, *args, **kwargs):
        status = UpdateStatus.get_or_create_status()
        if status.dataset_updated:
            # Return 1 and reset the flag
            status.dataset_updated = False
            status.save()
            return Response({'datasetUpdate': 1})
        else:
            return Response({'datasetUpdate': 0})
        
        
    

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .utils import update_folder_states  # Assuming the utility function is in utils.py

class DetectChangesView(APIView):
    def get(self, request):
        # Check for changes
        changes_detected = update_folder_states()
        
        if changes_detected:
            return Response({'datasetUpdate': 1}, status=status.HTTP_200_OK)
        else:
            return Response({'datasetUpdate': 0}, status=status.HTTP_200_OK)


from .models import Notification, Turnstile_S
import time


class FaceVerificationAndRelayAPI(APIView):

    def post(self, request, *args, **kwargs):
        facial_data = request.data.get('facial_data')
        turnstile_id = request.data.get('turnstile_id')
        user_folder_name = request.data.get('user_folder_name')  # Assuming the user's folder name is provided

        if not facial_data or not turnstile_id or not user_folder_name:
            return Response({"error": "Facial data, Turnstile ID, and User folder name are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Process the uploaded facial image
        uploaded_image = face_recognition.load_image_file(facial_data)
        uploaded_encoding = face_recognition.face_encodings(uploaded_image)

        if len(uploaded_encoding) == 0:
            return Response({"error": "No face found in the uploaded image."}, status=status.HTTP_400_BAD_REQUEST)

        uploaded_encoding = uploaded_encoding[0]

        # Verify face using the stored encodings
        face_matched = self.verify_face(user_folder_name, uploaded_encoding)

        if not face_matched:
            # Log notification
            Notification.objects.create(
                subject="Non-Matching Face Detected",
                description=f"A non-matching face was detected and the relay was actuated.",
                username="admin"
            )

            # Actuate relay
            self.actuate_relay(turnstile_id)

            return Response({"message": "Non-matching face detected. Relay actuated."}, status=status.HTTP_200_OK)

        return Response({"message": "Face matched successfully."}, status=status.HTTP_200_OK)

    def verify_face(self, user_folder_name, uploaded_encoding):
        # Load encodings from the pickle file
        user_folder = os.path.join('media', 'facial_data', user_folder_name)
        pickle_file_path = os.path.join(user_folder, 'encodings.pickle')

        if not os.path.exists(pickle_file_path):
            return False

        with open(pickle_file_path, 'rb') as f:
            data = pickle.load(f)

        known_encodings = data["encodings"]

        # Compare the uploaded encoding with known encodings
        matches = face_recognition.compare_faces(known_encodings, uploaded_encoding)

        return any(matches)

    def actuate_relay(self, turnstile_id):
        try:
            # Fetch the turnstile and set it to unlock (actuate the relay)
            turnstile = Turnstile_S.objects.get(turnstile_id=turnstile_id)
            turnstile.unlock = True
            turnstile.save()

            # Wait for 4 seconds
            time.sleep(4)

            # Reset the relay to locked (set unlock to False)
            turnstile.unlock = False
            turnstile.save()

        except Turnstile_S.DoesNotExist:
            # Handle the case where the turnstile does not exist
            pass
        
        
from .models import CustomUser, Site
from .serializers import SubAdminSiteSerializer

from rest_framework.views import APIView

class SubAdminSitesAPIView(APIView):
    def get(self, request, *args, **kwargs):
        email = request.query_params.get('email')
        if not email:
            return Response({'error': 'Email parameter is required.'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = CustomUser.objects.get(email=email)
            if not user.is_staff:
                return Response({'error': 'User is not a sub-admin.'}, status=status.HTTP_403_FORBIDDEN)
            
            # Fetch all sites associated with the sub-admin user
            sites = user.sites.all()
            # Pass the request context to the serializer
            serializer = SubAdminSiteSerializer(sites, many=True, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)



from django.views.decorators.csrf import csrf_exempt
from google.oauth2 import id_token
from google.auth.transport import requests
from django.http import JsonResponse

@csrf_exempt
def verify_google_token(request):
    if request.method == 'POST':
        try:
            token = request.POST.get('id_token')
            if not token:
                return JsonResponse({'status': 'error', 'message': 'ID token not provided'}, status=400)

            CLIENT_ID = '415241782180-top7pc23c2mhaog3skt1g7qalde1p7ms.apps.googleusercontent.com'
            idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)
            google_id = idinfo['sub']
            email = idinfo.get('email')
            name = idinfo.get('name', '')  
            user, created = UserEnrolled.objects.get_or_create(email=email, defaults={
                'name': name,
            })
            
            if not created:
                user.name = name
                user.save()
            return JsonResponse({'status': 'success', 'user_id': user.sr, 'email': user.email})
        except ValueError as e:
            return JsonResponse({'status': 'error', 'message': 'Invalid token: ' + str(e)}, status=400)
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)


from .serializers import UserWithSiteSerializer,PendingUserWithSiteSerializer

class SiteWorkersAPIView(APIView):
    def get(self, request, site):
        try:
           
            site = Site.objects.get(name__iexact=site)
            user_enrolled_list = UserEnrolled.objects.filter(site=site)
            serializer = UserWithSiteSerializer(user_enrolled_list, many=True, context={'request': request})
            return Response(serializer.data)
        except Site.DoesNotExist:
            return JsonResponse({'error': 'Site not found'}, status=404)
        

class PendingSiteWorkersAPIView(APIView):
    def get(self, request, site):
        try:
            site = Site.objects.get(name__iexact=site)
            # Filtering users by site, status 'pending', and tag_id being Null
            user_enrolled_list = UserEnrolled.objects.filter(site=site, status='pending', tag_id__isnull=True)
            serializer = PendingUserWithSiteSerializer(user_enrolled_list, many=True, context={'request': request})
            return Response(serializer.data)
        except Site.DoesNotExist:
            return JsonResponse({'error': 'Site not found'}, status=404)




from rest_framework import viewsets
from .serializers import NotTagUserSerializer


class UserEnrolledViewNoTag(viewsets.ViewSet):   # this is pending user api we want to modify this api to get data according to site
    def list(self, request):
        queryset = UserEnrolled.objects.filter(Q(tag_id__isnull=True) | Q(tag_id=''))
        serializer = UserEnrolledSerializer(queryset, many=True, context={'request': request})
        return Response(serializer.data)


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login
from social_django.utils import load_strategy, load_backend
from social_core.exceptions import AuthException
from social_core.backends.google import GoogleOAuth2
from .models import CustomUser  # Replace with your actual app name

@csrf_exempt
def google_login_view(request):
    if request.method == 'POST':
        token = request.POST.get('token')  # Use request.POST to get form data
        if not token:
            return JsonResponse({'error': 'Token is required'}, status=400)

        try:
            strategy = load_strategy(request)
            backend = load_backend(strategy=strategy, name='google-oauth2', redirect_uri=None)
            user = backend.do_auth(token)

            if user and user.is_active:
                # Log the user in
                login(request, user)
                
                # Return the user's email and other details if needed
                return JsonResponse({
                    'message': 'Login successful',
                    'user': {
                        'email': user.email
                        # Add other fields as needed
                    }
                }, status=200)
            else:
                return JsonResponse({'error': 'Login failed'}, status=401)

        except AuthException as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


import requests
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from app1.models import UserEnrolled  # Assuming 'app1' is the app where 'UserEnrolled' is defined
from django.contrib.auth.hashers import make_password  # Import password hash utilities
from django.utils.crypto import get_random_string  # To generate random passwords


class GoogleLoginAPIView(APIView):
    def post(self, request):
        token = request.data.get("token")
        
        if not token:
            return Response({"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Verify the token with Google
            idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), settings.GOOGLE_CLIENT_ID)
            
            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                return Response({"error": "Wrong issuer."}, status=status.HTTP_403_FORBIDDEN)

            # Get user's Google information
            email = idinfo['email']
            name = idinfo.get('name', '')
            picture_url = idinfo.get('picture', '')

            # Check if the user already exists in UserEnrolled
            try:
                user_enrolled = UserEnrolled.objects.get(email=email)
            except UserEnrolled.DoesNotExist:
                # Generate a random password for the user
                random_password = get_random_string(length=12)  # Generate a 12-character random password
                hashed_password = make_password(random_password)  # Hash the password
                
                # Create a new UserEnrolled if it doesn't exist
                user_enrolled = UserEnrolled.objects.create(
                    name=name,
                    email=email,
                    picture=picture_url,  # Save the profile picture URL or handle it accordingly
                    company_name="N/A",  # Default value, replace or fetch as needed
                    job_role="N/A",  # Default value
                    job_location="N/A",  # Default value
                    password=hashed_password  # Store the hashed password
                )
                user_enrolled.save()

            # Return user info, or any other tokens/authentication info you use
            return Response({
                "message": "User logged in successfully",
                "user": {
                    "id": user_enrolled.sr,
                    "email": user_enrolled.email,
                    "name": user_enrolled.name,
                }
            }, status=status.HTTP_200_OK)

        except ValueError:
            # Invalid token
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)


# from django.contrib.auth.models import User
# from rest_framework.response import Response
# from rest_framework.decorators import api_view
# from rest_framework import status


# @api_view(['POST'])
# def google_login_or_register(request):
#     email = request.data.get('email')
#     display_name = request.data.get('display_name')

#     if not email:
#         return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

#     try:
#         # Check if the user already exists in the database
#         user = UserEnrolled.objects.get(email=email)
#         return Response({
#             'message': 'User logged in successfully',
#             'email': user.email,
#         }, status=status.HTTP_200_OK)
#     except UserEnrolled.DoesNotExist:
#         # If user doesn't exist, create a new user
#         user = UserEnrolled.objects.create(
#             username=display_name,
#             email=email,
#             password=UserEnrolled.objects.make_random_password()  # Random password as it's a Google user
#         )
#         return Response({
#             'message': 'User registered successfully',
#             'email': user.email,
#         }, status=status.HTTP_201_CREATED)
        


from django.contrib.auth.hashers import make_password, check_password
from django.core.validators import FileExtensionValidator
from django.db import models
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status

@api_view(['POST'])
def google_login_or_register(request):
    email = request.data.get('email')
    display_name = request.data.get('display_name')

    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Check if the user already exists in the database
        user = UserEnrolled.objects.get(email=email)
        return Response({
            'message': 'User logged in successfully',
            'email': user.email,
        }, status=status.HTTP_200_OK)
    except UserEnrolled.DoesNotExist:
        # If user doesn't exist, create a new user
        user = UserEnrolled.objects.create(
            name=display_name,
            email=email,
            password=make_password('default_password'),  # Set a default password or handle it differently
            # You might need to set other required fields based on your model
        )
        return Response({
            'message': 'User registered successfully',
            'email': user.email,
        }, status=status.HTTP_201_CREATED)



# from django.contrib.auth.models import User
# from django.contrib.auth import authenticate
# from django.http import JsonResponse
# import json

# def apple_sign_in(request):
#     if request.method == 'POST':
#         data = json.loads(request.body)
#         email = data.get('email')
#         password = data.get('password')  # You can use the identity token as a password
#         first_name = data.get('first_name', '')

#         # Check if the user already exists
#         if User.objects.filter(email=email).exists():
#             # If the user exists, authenticate and log them in
#             user = authenticate(username=email, password=password)
#             if user is not None:
#                 return JsonResponse({'message': 'Login successful', 'status': 'login'}, status=200)
#             else:
#                 return JsonResponse({'message': 'Login failed'}, status=400)
#         else:
#             # If the user doesn't exist, register them
#             user = User.objects.create_user(username=email, email=email, first_name=first_name)
#             user.set_password(password)  # Optional password handling
#             user.save()
#             return JsonResponse({'message': 'User registered successfully', 'status': 'register'}, status=201)
        
        
    
# from django.contrib.auth.hashers import make_password
# from rest_framework.response import Response
# from rest_framework.decorators import api_view
# from rest_framework import status

# @api_view(['POST'])
# def apple_sign_in(request):
#     identity_token = request.data.get('identity_token')
#     first_name = request.data.get('first_name')
#     last_name = request.data.get('last_name')
#     email = request.data.get('email')

#     if not email or not identity_token:
#         return Response({'error': 'Email and identity token are required'}, status=status.HTTP_400_BAD_REQUEST)

#     # Expected identity token for validation (replace this with actual logic)
#     expected_identity_token = "001644.e56a6538ed9042ea9a08451676f91573.1258"

#     # Check if the identity token matches before proceeding with login or registration
#     if identity_token != expected_identity_token:
#         return Response({
#             'error': 'Identity token mismatch',
#             'identityToken': 'set: false',
#         }, status=status.HTTP_401_UNAUTHORIZED)

#     try:
#         # Check if the user already exists in the database
#         user = UserEnrolled.objects.get(email=email)
        
#         # If the identity token matches, log in the user
#         return Response({
#             'message': 'User logged in successfully',
#             'email': user.email,
#             'identityToken': 'set: true',
#         }, status=status.HTTP_200_OK)

#     except UserEnrolled.DoesNotExist:
#         # If the user doesn't exist, register them since identity_token was correct
#         name = f"{first_name} {last_name}" if first_name and last_name else "Unknown User"
#         user = UserEnrolled.objects.create(
#             name=name,
#             email=email,
#             password=make_password('default_password'),  # Set a default password or handle it differently
#         )
#         return Response({
#             'message': 'User registered successfully',
#             'email': user.email,
#             'identityToken': 'set: true',
#         }, status=status.HTTP_201_CREATED)




# from django.contrib.auth.hashers import make_password
# from rest_framework.decorators import api_view
# from rest_framework.response import Response
# from rest_framework import status
# from .models import UserEnrolled  # Import your UserEnrolled model

# @api_view(['POST'])
# def apple_sign_in(request):
#     # Extract data from the request
#     email = request.data.get('email')
#     first_name = request.data.get('first_name')
#     last_name = request.data.get('last_name')
#     identity_token = request.data.get('identity_token')

#     # Check if identity token is provided
#     if identity_token:
#         request.session['identity_token'] = identity_token

#     # Check if email is provided
#     if email:
#         # Check if user already exists
#         user, created = UserEnrolled.objects.get_or_create(
#             email=email,
#             defaults={
#                 'name': f"{first_name} {last_name}",
#                 'password': make_password(identity_token)  # Store the hashed identity token
#             }
#         )

#         if created:
#             # User was created successfully
#             return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
#         else:
#             # User already exists, log them in
#             return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)

#     # Handle the case where email is not provided
#     identity_token = request.session.get('identity_token')
#     if not identity_token:
#         return Response({'error': 'Identity token not found in session'}, status=status.HTTP_400_BAD_REQUEST)

#     try:
#         # Attempt to find the user with the hashed identity token
#         user = UserEnrolled.objects.get(password=identity_token)
#         return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
#     except UserEnrolled.DoesNotExist:
#         return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)



from django.contrib.auth.hashers import make_password
from django.utils.crypto import get_random_string
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import UserEnrolled

def generate_random_password(length=12):
    """Generate a random password."""
    return get_random_string(length)


@api_view(['POST'])
def apple_sign_in(request):
    # Extract data from the request
    email = request.data.get('email')
    first_name = request.data.get('first_name')
    last_name = request.data.get('last_name')
    identity_token = request.headers.get('Authorization', '').split(' ')[1]  # Extract identity token from Bearer token

    # Check if identity_token is provided
    if not identity_token:
        return Response({'error': 'Identity token is required'}, status=status.HTTP_400_BAD_REQUEST)

    # Handle first login with email
    if email:
        user, created = UserEnrolled.objects.get_or_create(
            email=email,
            defaults={
                'name': f"{first_name} {last_name}",
                'password': make_password(generate_random_password()),
                'identity_token': identity_token,
            }
        )
        if created:
            return Response({'message': 'User registered successfully', 'identity_token': identity_token}, status=status.HTTP_201_CREATED)
        else:
            # Update identity token for existing user
            user.identity_token = identity_token
            user.save()
            return Response({'message': 'Login successful', 'identity_token': identity_token}, status=status.HTTP_200_OK)
    else:
        # Handle subsequent login without email
        try:
            user = UserEnrolled.objects.get(identity_token=identity_token)
            return Response({'message': 'Login successful', 'identity_token': identity_token}, status=status.HTTP_200_OK)
        except UserEnrolled.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .models import UserEnrolled

@csrf_exempt
def check_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        userIdentifier = data.get('userIdentifier')

        # Check if the user exists in the database and get the user details
        user = UserEnrolled.objects.filter(userIdentifier=userIdentifier).first()

        if user:
            return JsonResponse({'exists': True, 'email': user.email})
        else:
            return JsonResponse({'exists': False, 'email': None})
    
    return JsonResponse({'error': 'Invalid request method'}, status=400)



# @csrf_exempt
# def create_user(request):
#     if request.method == 'POST':
#         data = json.loads(request.body)
#         userIdentifier = data.get('userIdentifier')
#         first_name = data.get('first_name')
#         family_name = data.get('family_name', '')  # Default to an empty string if family_name is not provided
#         email = data.get('email')

#         # Create a new user in the database
#         user = UserEnrolled.objects.create(
#             userIdentifier=userIdentifier,
#             first_name=first_name,
#             last_name=family_name,
#             email=email
#         )

#         return JsonResponse({'message': 'User created successfully', 'email': user.email})
    
#     return JsonResponse({'error': 'Invalid request method'}, status=400)


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import UserEnrolled
import json

@csrf_exempt
def create_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        userIdentifier = data.get('userIdentifier')
        first_name = data.get('first_name')
        family_name = data.get('family_name', '')  # Default to an empty string if family_name is not provided
        email = data.get('email')

        # Check if a user with the same email already exists
        try:
            user = UserEnrolled.objects.get(email=email)
            # User already exists, return a "Login successfully" message
            return JsonResponse({'message': 'Login successfully', 'email': user.email})
        except UserEnrolled.DoesNotExist:
            # Create a new user in the database
            user = UserEnrolled.objects.create(
                userIdentifier=userIdentifier,
                first_name=first_name,
                last_name=family_name,
                email=email
            )
            return JsonResponse({'message': 'User created successfully', 'email': user.email})
    
    return JsonResponse({'error': 'Invalid request method'}, status=400)




# from django.core.mail import send_mail
# from django.utils.crypto import get_random_string

# class ForgotPasswordView(View):
#     def post(self, request):
#         form = ForgotPasswordForm(request.POST)
#         if form.is_valid():
#             email = form.cleaned_data['email']
#             token = get_random_string(length=32)  # Generate a reset token
#             # Save the token associated with the user in the database
#             send_mail(
#                 'Password Reset',
#                 f'Use this token to reset your password: {token}',
#                 'from@example.com',
#                 [email],
#             )
#             return JsonResponse({'message': 'Reset link sent!'})
#         return JsonResponse({'error': 'Invalid email'}, status=400)



    
from django.core.mail import send_mail
from django.core.cache import cache
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from django.utils.crypto import get_random_string
from .models import UserEnrolled
from django.contrib.auth.hashers import make_password

@api_view(['POST'])
def send_otp(request):
    email = request.data.get('email')
    
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = UserEnrolled.objects.get(email=email)
        otp = get_random_string(length=6, allowed_chars='1234567890')
        # Store OTP in cache with a timeout of 10 minutes
        cache.set(email, otp, timeout=600)

        # Send OTP to user's email
        subject = 'Password Reset OTP'
        message = f'Your OTP for password reset is {otp}. It will expire in 10 minutes.'
        send_mail(subject, message, 'support@assure-tech.online', [email], fail_silently=False)

        return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)

    except UserEnrolled.DoesNotExist:
        return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
    
    
    
@api_view(['POST'])
def verify_otp(request):
    email = request.data.get('email')
    otp = request.data.get('otp')

    if not email or not otp:
        return Response({'error': 'Email and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)

    stored_otp = cache.get(email)
    if stored_otp and stored_otp == otp:
        return Response({'message': 'OTP verified successfully'}, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
    
    
    
from django.contrib.auth.hashers import make_password
from django.core.cache import cache
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status


import logging

logger = logging.getLogger(__name__)

@api_view(['POST'])
def reset_password(request):
    email = request.data.get('email')
    new_password = request.data.get('new_password')
    otp = request.data.get('otp')

    if not email or not new_password or not otp:
        return Response({'error': 'Email, new password, and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)

    stored_otp = cache.get(email)
    if stored_otp and stored_otp == otp:
        try:
            user = UserEnrolled.objects.get(email=email)
            hashed_password = make_password(new_password)
            logger.info(f'New hashed password: {hashed_password}')  # Log the hashed password
            user.password = hashed_password
            user.save()
            logger.info(f'Password saved for user: {user.email}')  # Log after saving
            cache.delete(email)
            return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
        except UserEnrolled.DoesNotExist:
            return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
    else:
        return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)




