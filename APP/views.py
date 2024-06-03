from datetime import datetime, timezone
import json
from turtle import pd

from django.core.mail import send_mail
from django.http import JsonResponse, HttpResponseRedirect, HttpResponse
import ftplib
import pandas as pd
import os
import django
from django.contrib import messages
import matplotlib
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from .forms import SignupForm, rootForm, TesteurForm, updateProfileForm
matplotlib.use('agg')
from matplotlib import pyplot as plt
from django.db.models import Q
# Configuration de Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "my_blog.settings")
django.setup()
from django.views.decorators.cache import never_cache
from .models import Testeur, IndicateurPerformance, InterfaceStatistique, CustomUser
from django.shortcuts import render, HttpResponse, redirect, get_object_or_404
from django.contrib.auth.models import User, Group
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, permission_required
from collections import Counter
import io
import base64
import numpy as np
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from .serializers import CustomUserSerialzers
from rest_framework.permissions import AllowAny
from django.http import JsonResponse



def index(request):
    return render(request, 'APP/index.html')


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def root_signup(request):
    accounts = CustomUser.objects.count()
    if accounts > 0:
        if request.META.get('HTTP_ACCEPT') == 'application/json':
            return JsonResponse({'error': 'Account already exists'}, status=400)
        else:
            return HttpResponseRedirect('/')
    else:
        if request.method == 'POST':
            if request.META.get('HTTP_ACCEPT') == 'application/json':
                data = json.loads(request.body)
                form = rootForm(data)
                
            else:
                form = rootForm(request.POST)

            if form.is_valid():
                print("form valid")
                form.save()
                if request.META.get('HTTP_ACCEPT') == 'application/json':
                    return JsonResponse({'success': 'Account created successfully'}, status=200)
                else:
                    return HttpResponseRedirect('/login/')
            else:
                if request.META.get('HTTP_ACCEPT') == 'application/json':
                    return JsonResponse({'errors': form.errors}, status=400)

        else:
            form = rootForm()

    return render(request, 'APP/root.html', {'form': form})


"""@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    if request.method == 'POST':
        serializer = CustomUserSerialzers(data = request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        accounts = CustomUser.objects.count()
        if accounts==0:
            return redirect('/admin_register/')
        elif request.user.is_authenticated:
            return redirect('/dashboard/')
        else:
            serializer = CustomUser()
    return Response({'error': 'methode is not allowd'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
"""


"""def register(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('/login/')
    else:
        accounts = CustomUser.objects.count()
        if accounts==0:
            return HttpResponseRedirect('/admin_register/')
        elif request.user.is_authenticated:
            return HttpResponseRedirect('/dashboard/')
        else:
            form = SignupForm()
    return render(request, 'APP/register.html', {'form': form})"""

@csrf_exempt
def loginView(request):
    if request.method == 'POST':
        if request.META.get('HTTP_ACCEPT') == 'application/json':
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON'}, status=400)
            
            email = data.get('email')
            password = data.get('password')
        else:
            email = request.POST.get('email')
            password = request.POST.get('password')

        if email and password:
            user = authenticate(request, username=email, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    if request.META.get('HTTP_ACCEPT') == 'application/json':
                        return JsonResponse({'success': 'Logged in successfully'}, status=200)
                    else:
                        return redirect('/dashboard/')
                else:
                    error_msg = 'Votre compte est en cours d\'approbation.'
                    if request.META.get('HTTP_ACCEPT') == 'application/json':
                        return JsonResponse({'error': error_msg}, status=403)
                    else:
                        messages.error(request, error_msg)
            else:
                error_msg = 'Invalid email or password'
                if request.META.get('HTTP_ACCEPT') == 'application/json':
                    return JsonResponse({'error': error_msg}, status=400)
                else:
                    messages.error(request, error_msg)
            return redirect('/login/')
        else:
            error_msg = 'Email and password are required'
            if request.META.get('HTTP_ACCEPT') == 'application/json':
                return JsonResponse({'error': error_msg}, status=400)
            else:
                messages.error(request, error_msg)
            return redirect('/login/')
    else:
        return render(request, 'APP/login.html')
"""@api_view(['POST'])
@permission_classes([AllowAny])
def loginView(request):
    if request.method == 'POST':
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(request, username=email, password=password)
        if user:
            login(request, user)
            return JsonResponse({'message': 'Connexion réussie'})
        else:
            return JsonResponse({'error': 'Email ou mot de passe invalide'}, status=400)"""

@csrf_exempt
@login_required(login_url='login')
def approuve_user(request, pk):
    print("Request method:", request.method)
    print("User is admin:", request.user.is_admin)
    
    if request.user.is_admin:
        user = get_object_or_404(CustomUser, pk=pk)
        user.is_active = True
        user.save()
        if request.META.get('HTTP_ACCEPT') == 'application/json':
            return JsonResponse({'success': 'User approved successfully'}, status=204)
        else:
            return HttpResponseRedirect('/users/')
    else:
        print("Unauthorized access attempt")
        if request.META.get('HTTP_ACCEPT') == 'application/json':
            return JsonResponse({'error': 'Unauthorized'}, status=403)
        else:
            return HttpResponseRedirect('/dashboard/')
@csrf_exempt
@login_required(login_url='login')
def deny_user(request, pk):
    if request.user.is_admin:
        try:
            theuser = CustomUser.objects.get(pk=pk)
            theuser.delete()
            if request.META.get('HTTP_ACCEPT') == 'application/json':
                return JsonResponse({'success': 'User deleted successfully'}, status=200)
            else:
                return HttpResponseRedirect('/users/')
        except CustomUser.DoesNotExist:
            if request.META.get('HTTP_ACCEPT') == 'application/json':
                return JsonResponse({'error': 'User not found'}, status=404)
            else:
                return HttpResponseRedirect('/users/')
    else:
        if request.META.get('HTTP_ACCEPT') == 'application/json':
            return JsonResponse({'error': 'Unauthorized'}, status=403)
        else:
            return HttpResponseRedirect('/dashboard/')




@login_required(login_url='login')
def inserttesteur(request):
    if request.user.is_admin:
        if request.method == 'POST':
            name = request.POST.get('name')
            username = request.POST.get('username')
            ligne = request.POST.get('ligne')
            host = request.POST.get('host')
            password = request.POST.get('password')
            chemin = request.POST.get('chemin')
            testeur = Testeur(name=name, username=username, ligne=ligne, host=host, password=password, chemin=chemin)
            testeur.save()
            if request.META.get('HTTP_ACCEPT') == 'application/json':
                return JsonResponse({'success': 'Testeur inserted successfully'}, status=201)
            else:
                return HttpResponseRedirect('/list_testeurs/')

        return render(request, 'APP/inserttesteur.html', {})
    else:
        if request.META.get('HTTP_ACCEPT') == 'application/json':
            return JsonResponse({'error': 'Unauthorized'}, status=403)
        else:
            return HttpResponseRedirect('/dashboard/')
@csrf_exempt     
def inserttesteur_app(request,email):
    user = CustomUser.objects.filter(email = email).first()
    if not user.is_admin:
        if request.method == 'POST' :
            try:
                data = json.loads(request.body)
                name = data.get('name')
                username = data.get('username')
                ligne = data.get('ligne')
                host = data.get('host')
                password = data.get('password')
                chemin = data.get('chemin')

                if not all([name, username, ligne, host, password, chemin]):
                    return JsonResponse({'error': 'All fields are required'}, status=400)

                testeur = Testeur(name=name, username=username, ligne=ligne, host=host, password=password, chemin=chemin)
                testeur.save()
                return JsonResponse({'success': 'Testeur inserted successfully'}, status=201)
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON'}, status=400)
        else:
            return JsonResponse({'error': 'Invalid request'}, status=400)
    else:
        return JsonResponse({'error': 'Unauthorized'}, status=403)




@login_required(login_url='login')
def list_testeurs(request):
    if request.user.is_admin:
        testeurs = Testeur.objects.all()
        if request.META.get('HTTP_ACCEPT') == 'application/json':
            testeurs_data = [{'name': testeur.name, 'username': testeur.username, 'ligne': testeur.ligne, 'host': testeur.host, 'chemin': testeur.chemin} for testeur in testeurs]
            return JsonResponse({'testeurs': testeurs_data})
        else:
            return render(request, 'APP/testeurs.html', {'testeurs': testeurs})
    else:
        if request.META.get('HTTP_ACCEPT') == 'application/json':
            return JsonResponse({'error': 'Unauthorized'}, status=403)
        else:
            return HttpResponseRedirect('/dashboard/')
@csrf_exempt
def list_testeurs_app(request,email):
    user = CustomUser.objects.filter(email = email).first()
    if not user.is_admin:
        if request.META.get('HTTP_ACCEPT') == 'application/json':
            testeurs = Testeur.objects.all()
            testeurs_data = [
                {
                    'id':testeur.id,
                    'name': testeur.name,
                    'username': testeur.username,
                    'ligne': testeur.ligne,
                    'host': testeur.host,
                    'chemin': testeur.chemin,
                    'password':testeur.password
                } for testeur in testeurs
            ]
            return JsonResponse({'testeurs': testeurs_data})
        else:
            return JsonResponse({'error': 'Accept header must be application/json'}, status=400)
    else:
        return JsonResponse({'error': 'Unauthorized'}, status=403)

@csrf_exempt
@login_required(login_url='login')
def edit_testeur(request, pk):
    testeur = get_object_or_404(Testeur, pk=pk)
    if request.user.is_admin:
        if request.method == "POST":
            form = TesteurForm(request.POST, instance=testeur)
            if form.is_valid():
                form.save()
                if request.META.get('HTTP_ACCEPT') == 'application/json':
                    return JsonResponse({'success': 'Testeur updated successfully'}, status=200)
                else:
                    return HttpResponseRedirect('/list_testeurs/')
        else:
            form = TesteurForm(instance=testeur)
        return render(request, 'APP/edit_testeur.html', {'form': form})
    else:
        if request.META.get('HTTP_ACCEPT') == 'application/json':
            return JsonResponse({'error': 'Unauthorized'}, status=403)
        else:
            return HttpResponseRedirect('/dashboard/')
@csrf_exempt
def edit_testeur_app(request, email, pk):
    user = CustomUser.objects.filter(email=email).first()
    if  user.is_admin:
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    try:
        testeur = Testeur.objects.get(pk=pk)
    except Testeur.DoesNotExist:
        return JsonResponse({'error': 'Testeur not found'}, status=404)

    if request.method == "POST":
        try:
            data = json.loads(request.body)
            name = data.get('name')
            username = data.get('username')
            ligne = data.get('ligne')
            password = data.get('password')
            host = data.get('host')
            chemin = data.get('chemin')

            testeur.name = name
            testeur.username = username
            testeur.ligne = ligne
            testeur.password = password
            testeur.host = host
            testeur.chemin = chemin

            testeur.save()
            print(testeur.username)
            return JsonResponse({'success': 'Testeur updated successfully'}, status=200)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


User = get_user_model()
@csrf_exempt
def delete_testeur(request, testeur_id):
    try:
        testeur = Testeur.objects.get(id=testeur_id)
        testeur.delete()
        return JsonResponse({'message': 'User deleted successfully'}, status=204)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

def adduser(request):
    if request.user.is_admin :
        if request.method == 'POST':
            form = SignupForm(request.POST)
            if form.is_valid():
                form.save()
                return redirect('/users/')
        else:
            form = SignupForm()
        return render(request, 'APP/adduser.html', {'form': form})
    else:
        return HttpResponseRedirect('/dashboard/')
@csrf_exempt
def add_user_app(request, email):
    user = CustomUser.objects.filter(email=email).first()
    if  user.is_admin:
        if request.method == 'POST' :
            try:
                data = json.loads(request.body)
                form = SignupForm(data)
                if form.is_valid():
                    form.save()
                    return JsonResponse({'success': 'User added successfully'}, status=201)
                else:
                    return JsonResponse({'errors': form.errors}, status=400)
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON'}, status=400)
        else:
            return JsonResponse({'error': 'Invalid request'}, status=400)
    else:
        return JsonResponse({'error': 'Unauthorized'}, status=403)

@login_required(login_url='login')
def users(request):
    if request.user.is_admin:
        users = CustomUser.objects.filter(is_active=True)
        pusers = CustomUser.objects.filter(Q(is_active=None)| Q(is_active=False))
        return render(request, 'APP/users.html', {'users': users, 'pusers': pusers})
    else:
        return HttpResponseRedirect('/dashboard/')
@csrf_exempt  
def get_users(request,email):
    user = CustomUser.objects.filter(email = email).first()
    if  not user.is_admin:
        users = CustomUser.objects.filter(is_active=True)
        pusers = CustomUser.objects.filter(Q(is_active=None) | Q(is_active=False))
        users_data = [{'id': user.id, 'username': user.prenom, 'email': user.email, 'is_active': user.is_active} for user in users]
        pusers_data = [{'id': user.id, 'username': user.prenom, 'email': user.email, 'is_active': user.is_active} for user in pusers]
        data = {'active_users': users_data, 'inactive_users': pusers_data}
        print(data)
        return JsonResponse(data, safe=False)  # Safe is set to False because we are returning a list of dictionaries
    else:
        return JsonResponse({'error': 'Access Denied'}, status=403)

@login_required(login_url='login')
def ModifyUser(request,pk):
    if request.user.is_admin :
        user = CustomUser.objects.get(pk=pk)
        if request.method == 'POST':
            form = updateProfileForm(data=request.POST, instance=user)
            if form.is_valid():
                form.save()
                return HttpResponseRedirect('/users/')
        else:
            form = updateProfileForm(instance=user)
        return render(request,'APP/ModifyUser.html', {'form':form})
    else:
        return HttpResponseRedirect('/dashboard/')

User = get_user_model()

def delete_user(request, user_id):
        try:
            user = User.objects.get(id=user_id)
            user.delete()
            return JsonResponse({'message': 'User deleted successfully'}, status=204)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
@csrf_exempt     
def delete_user_app(request, email):
        try:
            user = CustomUser.objects.get(email = email)
            user.delete()
            return JsonResponse({'message': 'User deleted successfully'}, status=204)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)






def listeligne(request):
    # Votre logique pour récupérer et traiter la liste des lignes
    lignes = ['S15', 'S25', 'ESB/ESO ROTATIF']
    if request.META.get('HTTP_ACCEPT') == 'application/json':
        return JsonResponse({'lignes': lignes})
    else:
        return render(request, 'APP/listeligne.html', {'lignes': lignes})

def S15(request):
    testeurs_s15 = Testeur.objects.filter(ligne='S15')
    if request.META.get('HTTP_ACCEPT') == 'application/json':
        # Convertir les données en format JSON si la demande est JSON
        testeurs_data = [{'name': testeur.name, 'username': testeur.username} for testeur in testeurs_s15]
        return JsonResponse({'testeurs_s15': testeurs_data})
    else:
        return render(request, 'APP/S15.html', {'testeurs_s15': testeurs_s15})

def s25_list(request):
    testeurs_s25 = Testeur.objects.filter(ligne='S25')
    if request.META.get('HTTP_ACCEPT') == 'application/json':
        # Convertir les données en format JSON si la demande est JSON
        testeurs_data = [{'name': testeur.name, 'username': testeur.username} for testeur in testeurs_s25]
        return JsonResponse({'testeurs_s25': testeurs_data})
    else:
        return render(request, 'APP/S25.html', {'testeurs_s25': testeurs_s25})

def esb_eso_rotatif_list(request):
    testeurs_esb_eso_rotatif = Testeur.objects.filter(ligne='ESB/ESO Rotatif')
    if request.META.get('HTTP_ACCEPT') == 'application/json':
        # Convertir les données en format JSON si la demande est JSON
        testeurs_data = [{'name': testeur.name, 'username': testeur.username} for testeur in testeurs_esb_eso_rotatif]
        return JsonResponse({'testeurs_esb_eso_rotatif': testeurs_data})
    else:
        return render(request, 'APP/esb_eso_rotatif_list.html', {'testeurs_esb_eso_rotatif': testeurs_esb_eso_rotatif})


def dashboard(request):
    return render (request,'APP/home.html')

def extraire_donnees_via_ftp(testeur, selected_date):
    try:
        file_path_remote = f"{testeur.chemin}/{selected_date.year}/{selected_date.month:02d}/{selected_date.day:02d}.CSV"

        ftp = ftplib.FTP(testeur.host)
        print("Connexion FTP établie")

        if testeur.username and testeur.password:
            print(f"Nom d'utilisateur: {testeur.username}, Mot de passe: {testeur.password}")
            ftp.login(user=testeur.username, passwd=testeur.password)

        else:
            print("Aucun nom d'utilisateur ni mot de passe fourni. Connexion anonyme.")
            ftp.login()

        print("Connexion FTP réussie")

        file_name = os.path.basename(file_path_remote)

        with open(file_name, 'wb') as fichier_local:
            ftp.retrbinary('RETR ' + file_path_remote, fichier_local.write)

        df = pd.read_csv(file_name, delimiter=';', encoding='utf-8')
        try:
            df['Date'] = pd.to_datetime(df['Date'], format='%d/%m/%Y', errors='raise')  # Changement du format ici
        except ValueError:
            df['Date'] = pd.to_datetime(df['Date'], format='%d/%m/%y', errors='coerce')

        df = df.dropna(subset=['Date'])

        df['Heure'] = pd.to_datetime(df['Heure'], format='%H:%M:%S').dt.hour

        
        fpy_by_two_hours = df.groupby(df['Heure'] // 2 * 2).apply(
            lambda x: (x[x['Code err'] == 0].shape[0] / len(x)) * 100)

        last_hour = max(df['Heure'])
        last_hour_data = df[df['Heure'] == last_hour]
        if len(last_hour_data) > 0:
            last_fpy = (last_hour_data[last_hour_data['Code err'] == 0].shape[0] / len(last_hour_data)) * 100
            fpy_by_two_hours[last_hour] = last_fpy

        # Créer le graphique
        fig1, ax1 = plt.subplots(figsize=(10, 6))
        fpy_by_two_hours.sort_index().plot(kind='line', marker='o', ax=ax1)  # Tri des index pour l'affichage correct
        ax1.set_title('FPY en fonction du temps')
        dates = df['Date'].dt.strftime('%d/%m/%Y').unique()
        ax1.annotate(', '.join(dates), xy=(0.5, -0.2), xycoords='axes fraction', ha='center')
        ax1.set_xlabel('Heure')
        ax1.set_ylabel('FPY (%)')
        ax1.grid(True)
        ax1.set_xticks(range(0, 25, 2))
        ax1.set_xticklabels(['00h', '02h', '04h', '06h', '08h', '10h', '12h', '14h', '16h', '18h', '20h', '22h', '00h'])

        # Convert graph 1 to image format
        buffer1 = io.BytesIO()
        fig1.savefig(buffer1, format='png')
        buffer1.seek(0)
        graph1 = base64.b64encode(buffer1.getvalue()).decode('utf-8')
        plt.close(fig1)


        # Data processing for graph 3
        # Convertir les codes d'erreur en entiers
        df['Code err'] = df['Code err'].astype(int)
        # Filtrer les codes d'erreur différents de zéro
        codes_err_non_zero = df[df['Code err'] != 0]['Code err']
        # Count occurrences of each error code
        compteur = codes_err_non_zero.value_counts()
        # Sort values by index for ordered display
        compteur_sorted = compteur.sort_index()
        # Create bar chart
        fig3, ax3 = plt.subplots(figsize=(10, 6))
        compteur_sorted.plot(kind='bar', ax=ax3)
        # Add labels
        ax3.set_title('Error Code Occurrences')
        ax3.set_xlabel('Error Code')
        ax3.set_ylabel('Occurrences')
        # Reverse the x-axis
        ax3.invert_xaxis()

        # Convert graph 3 to image format
        buffer3 = io.BytesIO()
        fig3.savefig(buffer3, format='png')
        buffer3.seek(0)
        graph3 = base64.b64encode(buffer3.getvalue()).decode('utf-8')
        plt.close(fig3)  # Close the figure to release resources

        # Calculate global statistics
        nb_pieces_bonnes_global = df[df['Code err'] == 0].shape[0]
        nb_pieces_mauvaises_global = df[df['Code err'] != 0].shape[0]
        nb_pieces_total_global = len(df)

        if nb_pieces_total_global != 0:
            fpy_global = (nb_pieces_bonnes_global / nb_pieces_total_global) * 100
            fpy_global = round(fpy_global,2)
        else:
            fpy_global = 0

        # Save data to the database
        # Determine the top_defaut indicator
        top_defaut = df[df['Code err'] != 0]['Code err'].value_counts().idxmax()

        # Save global statistics to the IndicateurPerformance model
        indicateur_performance_global = IndicateurPerformance.objects.create(
            testeur=testeur,
            fpy=fpy_global,
            pieces_bonnes=nb_pieces_bonnes_global,
            pieces_total=nb_pieces_total_global,
            pieces_mauvaises=nb_pieces_mauvaises_global,
            top_defaut=top_defaut
        )
        indicateur_performance_global.save()

        # Calculate FPY by interface
        for interface, data in df.groupby('Interface'):
            nb_pieces_bonnes_interface = data[data['Code err'] == 0].shape[0]
            nb_pieces_total_interface = len(data)
            nb_pieces_mauvaises_interface = nb_pieces_total_interface - nb_pieces_bonnes_interface

            if nb_pieces_total_interface != 0:
                fpy_interface = (nb_pieces_bonnes_interface / nb_pieces_total_interface) * 100
            else:
                fpy_interface = 0

            # Calculate top_defaut by interface
            top_defaut_interface = Counter(data[data['Code err'] != 0]['Code err']).most_common(1)[0][0]
            # Save interface statistics to the InterfaceStatistique model
            indicateur_performance_interface = InterfaceStatistique.objects.create(
                interface=interface,
                fpy_interface=fpy_interface,
                pieces_bonnes_interface=nb_pieces_bonnes_interface,
                pieces_mauvaises_interface=nb_pieces_mauvaises_interface,
                pieces_total_interface=nb_pieces_total_interface,
                top_defaut_interface=top_defaut_interface
            )
            indicateur_performance_interface.save()

        # Get the latest 8 InterfaceStatistique objects ordered by id
        interface_stats = InterfaceStatistique.objects.order_by('-id')[:8][::-1]

        # Extract interface names and corresponding FPY% values
        interfaces = [stat.interface for stat in interface_stats]
        fpy_percentages = [stat.fpy_interface for stat in interface_stats]

        # Create the graph
        fig2, ax2 = plt.subplots(figsize=(10, 6))
        ax2.bar(interfaces, fpy_percentages)
        ax2.set_title('FPY% by Interface')
        ax2.set_xlabel('Interface')
        ax2.set_ylabel('FPY (%)')
        ax2.grid(True)
        plt.xticks(rotation=45, ha='right')

        # Convert graph 2 to image format
        buffer2 = io.BytesIO()
        fig2.savefig(buffer2, format='png')
        buffer2.seek(0)
        graph2 = base64.b64encode(buffer2.getvalue()).decode('utf-8')
        plt.close(fig2)  # Close the figure to release resources

        print("Data saved to the database successfully.")

        return graph1, graph2, graph3, nb_pieces_bonnes_global, nb_pieces_mauvaises_global, nb_pieces_total_global, fpy_global
    except ftplib.all_errors as e:
        print(f"FTP Connection or File Download Error: {e}")
    except Exception as e:
        print(f"Error during data download and processing: {e}")
    finally:
        # Close the FTP connection
        if 'ftp' in locals():
            ftp.quit()


from django.shortcuts import render
from .models import Testeur, IndicateurPerformance, InterfaceStatistique


from django.utils import timezone

def detailtesteur(request, testeur_id):
    testeur = Testeur.objects.get(pk=testeur_id)
    selected_date = None
    current_date = timezone.now().date()

    if request.method == 'POST':
        selected_date_str = request.POST.get('selected_date')
        if selected_date_str:
            selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d')

        graph1, graph2, graph3, nb_pieces_bonnes_global, nb_pieces_mauvaises_global, nb_pieces_total_global, fpy_global = extraire_donnees_via_ftp(
            testeur, selected_date)

        if request.META.get('HTTP_ACCEPT') == 'application/json':
            data = {
                'testeur': testeur.id,
                'graph1': graph1,
                'graph2': graph2,
                'graph3': graph3,
                'nb_pieces_bonnes_global': nb_pieces_bonnes_global,
                'nb_pieces_mauvaises_global': nb_pieces_mauvaises_global,
                'nb_pieces_total_global': nb_pieces_total_global,
                'fpy_global': fpy_global,
                'selected_date': selected_date_str,
                'current_date': current_date.strftime('%Y-%m-%d')
            }
            return JsonResponse(data)
        else:
            return render(request, 'APP/detailtesteur.html', {
                'testeur': testeur,
                'graph1': graph1,
                'graph2': graph2,
                'graph3': graph3,
                'nb_pieces_bonnes_global': nb_pieces_bonnes_global,
                'nb_pieces_mauvaises_global': nb_pieces_mauvaises_global,
                'nb_pieces_total_global': nb_pieces_total_global,
                'fpy_global': fpy_global,
                'selected_date': selected_date,
                'current_date': current_date
            })

    return render(request, 'APP/detailtesteur.html', {
        'testeur': testeur,
        'selected_date': selected_date,
        'current_date': current_date
    })

@login_required(login_url='login')
def user_logout(request):
    logout(request)
    if request.META.get('HTTP_ACCEPT') == 'application/json':
        return JsonResponse({'message': 'User logged out successfully'}, status=200)
    else:
        return HttpResponseRedirect('/')
@csrf_exempt

def Userprofile(request):
    pk = request.user.id
    user = CustomUser.objects.get(pk=pk)
    
    if request.method == 'POST':
        if request.META.get('CONTENT_TYPE') == 'application/json':
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON'}, status=400)
            
            form = updateProfileForm(data=data, instance=user)
        else:
            form = updateProfileForm(data=request.POST, instance=user)
        
        if form.is_valid():
            form.save()
            if request.META.get('CONTENT_TYPE') == 'application/json':
                return JsonResponse({'message': 'Profile updated successfully'}, status=201)
            else:
                return HttpResponseRedirect('/users/')
    else:
        form = updateProfileForm(instance=user)
    
    return render(request, 'APP/modify_account.html', {'form': form})

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
import json

@csrf_exempt
def update_user_profile(request,email):
    if request.method == 'POST':
        
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON'}, status=400)
            
            user = CustomUser.objects.filter(email = email).first()
            prenom = data.get('prenom')
            nom = data.get('nom')
            emaill = data.get('email')
            print(emaill,prenom,nom)
            
            if prenom and nom and emaill and email:
                user.prenom = prenom
                user.nom = nom
                user.email = emaill
                user.save()
                return JsonResponse({'message': 'Profile updated successfully'}, status=200)
            else:
                return JsonResponse({'error': 'Missing fields'}, status=400)
        
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    
@csrf_exempt
def update_user_profile_admin(request,email):
    if request.method == 'POST':
        
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON'}, status=400)
            
           
            prenom = data.get('prenom')
            nom = data.get('nom')
            emaill = data.get('email')
            print(emaill,prenom,nom)
            user = CustomUser.objects.filter(email = emaill).first()
            
            if prenom and nom and emaill and email:
                user.prenom = prenom
                user.nom = nom
                user.email = emaill
                user.save()
                return JsonResponse({'message': 'Profile updated successfully'}, status=200)
            else:
                return JsonResponse({'error': 'Missing fields'}, status=400)
        
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def register(request):
    print("Request method:", request.method)
    print("Request headers:", request.META)
    if request.META.get('HTTP_ACCEPT') == 'application/json':
        print("JSON request received")
        if not request.body:
            print("Empty request body")
            return JsonResponse({'error': 'Empty request body'}, status=400)
        try:
            body_unicode = request.body.decode('utf-8')
            if not body_unicode:
                raise ValueError("Empty body after decoding")
            data = json.loads(body_unicode)
            print("Parsed JSON data:", data)
            form = SignupForm(data)
        except (json.JSONDecodeError, ValueError) as e:
            print("JSON decode error or empty body:", str(e))
            return JsonResponse({'error': 'Invalid JSON or empty body'}, status=400)
    else:
        print("Form request received")
        form = SignupForm(request.POST)

    print("Form valid:", form.is_valid())

    if form.is_valid():
        form.save()
        if request.META.get('HTTP_ACCEPT') == 'application/json':
            print("Returning 201 Created")
            return JsonResponse({'message': 'User registered successfully'}, status=201)
        else:
            print("Redirecting to /login/")
            return redirect('/login/')
    else:
        print("Form errors:", form.errors)
        if request.META.get('HTTP_ACCEPT') == 'application/json':
            return JsonResponse({'errors': form.errors}, status=400)
        else:
            return render(request, 'APP/register.html', {'form': form})



