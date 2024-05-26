from datetime import datetime, timezone
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
from .forms import SignupForm, rootForm, TesteurForm
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




def index(request):
    return render(request, 'APP/index.html')

''' def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 != password2:
            messages.error(request, "Votre mot de passe et la confirmation ne sont pas identiques !!")
            return render(request, 'APP/register.html')
        else:
            # Créez un nouvel utilisateur, mais ne l'activez pas immédiatement
            users = CustomUser.objects.create_user(
                username=username,
                email=email,
                password=password1,
                est_approuve=False
            )
            users.save()
            messages.success(request, "Votre compte a été créé avec succès. Veuillez attendre l'approbation.")
            return redirect('login')

    return render(request, 'APP/register.html') '''

def root_signup(request):
    accounts = CustomUser.objects.count()
    if accounts>0:
        return HttpResponseRedirect('/')
    else:
        if request.method == 'POST':
            form = rootForm(request.POST)
            if form.is_valid():
                form.save()  
                return HttpResponseRedirect('/login/')
        else:
            form = rootForm()
    return render(request, 'APP/root.html', {'form': form})

def register(request):
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
    return render(request, 'APP/register.html', {'form': form})


def loginView(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = authenticate(request, username=email, password=password)  # Use 'email' as the username field
        if user is not None:
            if user.is_active:
                login(request, user)
                return redirect('/dashboard/')
            else:
                messages.error(request, "Votre compte est en cours d'approbation.")
        else:
            messages.error(request, "Invalid email or password")
        return redirect('/login/')
    else:
        # S'il s'agit d'une requête GET, afficher le formulaire de connexion
        return render(request, 'APP/login.html')

@login_required(login_url='login')
def approuve_user(request,pk):
    if request.user.is_admin:
        user = CustomUser.objects.filter(pk=pk).update(is_active=True)
        return HttpResponseRedirect('/users/')
    else:
        return HttpResponseRedirect('/dashboard/')

@login_required(login_url='login')
def deny_user(request,pk):
    if request.user.is_admin:
        theuser = CustomUser.objects.get(pk=pk)
        user = CustomUser.objects.filter(pk=pk).delete()
        return HttpResponseRedirect('/users/')
    else:
        return HttpResponseRedirect('/dashboard/')
        
"""def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if User is not None:
            login(request, user)
            return redirect('/dashboard')  # Correction: Suppression de la virgule en trop
        else:
            # L'authentification a échoué, renvoyer un message d'erreur
            return render(request, 'APP/login.html', {'error_message': 'Authentication failed. Please try again.'})
    else:
        # S'il s'agit d'une requête GET, afficher le formulaire de connexion
        return render(request, 'APP/login.html')
"""


def forget_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        # Vérifier si l'utilisateur avec cette adresse e-mail existe
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return HttpResponse("Aucun utilisateur avec cette adresse e-mail")

        # Générer le lien de réinitialisation du mot de passe
        reset_link = request.build_absolute_uri(reverse('password_reset_confirm'))

        # Envoyer l'e-mail de réinitialisation de mot de passe
        subject = 'Réinitialisation de mot de passe'
        message = f"Pour réinitialiser votre mot de passe, veuillez cliquer sur le lien suivant: {reset_link}"
        send_mail(subject, message, 'from@example.com', [email])

        return HttpResponse(
            "Un e-mail de réinitialisation de mot de passe a été envoyé. Veuillez vérifier votre boîte de réception.")

    return render(request, 'APP/forgetpassword.html')

def grant_admin_access(request, user_id):
    user = get_object_or_404(CustomUser, pk=user_id)
    user.is_superuser = True
    user.save()
    return redirect('listusers')

def remove_admin_access(request, user_id):
    user = get_object_or_404(CustomUser, pk=user_id)
    user.is_superuser = False
    user.save()
    return redirect('listusers')

def HomePage(request):
    # Récupérer l'utilisateur connecté
    user = request.user

    # Récupérer la liste des utilisateurs
    users = CustomUser.objects.all()

    # Vérifier si l'utilisateur est administrateur
    if user.is_superuser:
        # Si l'utilisateur est administrateur, redirigez-le vers la page d'administration
        return render(request, 'APP/admin_home.html', {'users': users})
    else:
        # Si l'utilisateur n'est pas administrateur, redirigez-le vers la page utilisateur
        return render(request, 'APP/user_home.html', {'users': users})

def inserttesteur(request):
    if request.user.is_admin:
        if request.method == 'POST':
            name = request.POST.get('name')
            username = request.POST.get('username')
            ligne = request.POST.get('ligne')
            host = request.POST.get('host')
            password = request.POST.get('password')
            chemin = request.POST.get('chemin')
            # Create a new CustomUser instance and save it
            testeur = Testeur(name=name,username=username, ligne=ligne, host=host,password=password,chemin=chemin)
            testeur.save()
            return HttpResponseRedirect('/list_testeurs/')

        return render(request, 'APP/inserttesteur.html', {})
    else:
        return HttpResponseRedirect('/dashboard/')


def insertuser(request):
    if request.method == 'POST':
        name = request.POST.get('username')
        email = request.POST.get('email')
        pass1 = request.POST.get('password')
        # Create a new CustomUser instance and save it
        user = User(username=name, email=email, password=pass1)
        user.save()
        return render(request, 'APP/index.html', {})
    else:
        # Handle GET requests appropriately, maybe redirect to another page
        pass

def list_testeurs(request):
    if request.user.is_admin:
        testeurs = Testeur.objects.all()
        return render(request, 'APP/testeurs.html', {'testeurs': testeurs})
    else:
        return HttpResponseRedirect('/dashboard/')


''' def edit_testeur(request, testeur_id):
    testeur = get_object_or_404(Testeur, id=testeur_id)
    if request.method == 'POST':
        testeur.name = request.POST.get('name')
        testeur.ligne = request.POST.get('ligne')
        testeur.password = request.POST.get('password')
        testeur.host = request.POST.get('host')
        testeur.chemin = request.POST.get('chemin')
        testeur.save()
        return HttpResponseRedirect('/list_testeurs/')
    else:
        return render(request, 'edit_testeur.html', {'testeur': testeur}) '''

def edit_testeur(request, pk):
    testeur = get_object_or_404(Testeur, pk=pk)
    if request.method == "POST":
        form = TesteurForm(request.POST, instance=testeur)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect('/list_testeurs/')  # Redirect to a detail view or any other view
    else:
        form = TesteurForm(instance=testeur)
    return render(request, 'APP/edit_testeur.html', {'form': form})


def delete_testeur(request, testeur_id):
    try:
        testeur = Testeur.objects.get(id=testeur_id)
        testeur.delete()
        return JsonResponse({'message': 'User deleted successfully'}, status=204)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

def save_testeur_changes(request, testeur_id):
    if request.method == 'POST':
            testeur = get_object_or_404(Testeur, id=testeur_id)
            testeur.name = request.POST.get('name')
            testeur.ligne = request.POST.get('ligne')
            testeur.host = request.POST.get('host')
            testeur.password = request.POST.get('password')
            testeur.chemin = request.POST.get('chemin')
            testeur.save()
            return HttpResponseRedirect('/')

@login_required(login_url='login')
def users(request):
    if request.user.is_admin:
        users = CustomUser.objects.filter(is_active=True)
        pusers = CustomUser.objects.filter(Q(is_active=None)| Q(is_active=False))
        return render(request, 'APP/users.html', {'users': users, 'pusers': pusers})
    else:
        return HttpResponseRedirect('/dashboard/')


def listusers(request):
    users = CustomUser.objects.all()  # Retrieve all users from the database
    return render(request, 'APP/listusers.html', {'users': users})

def delete_user(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        user.delete()
        return JsonResponse({'message': 'User deleted successfully'}, status=204)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

def edit_user(request, user_id):
        user = get_object_or_404(User, id=user_id)
        # Render the edit user page with the user data
        return render(request, 'APP/edit_user.html', {'user': user})

def save_user_changes(request, user_id):
    if request.method == 'POST':
        user = get_object_or_404(User, id=user_id)
        user.username = request.POST.get('username')
        user.email = request.POST.get('email')
        user.save()
        return HttpResponseRedirect('/')


def listeligne(request):
    # Votre logique pour récupérer et traiter la liste des lignes
    ligne = ['S15', 'S25', 'ESB/ESO ROTATIF']
    return render(request, 'APP/listeligne.html', {'lignes': ligne})


def S15(request):
    testeurs_s15 = Testeur.objects.filter(ligne='S15')
    return render(request, 'APP/S15.html', {'testeurs_s15': testeurs_s15})



def s25_list(request):
    testeurs_s25 = Testeur.objects.filter(ligne='S25')
    return render(request, 'APP/S25.html', {'testeurs_s25': testeurs_s25})

def esb_eso_rotatif_list(request):
    testeurs_esb_eso_rotatif = Testeur.objects.filter(ligne='ESB/ESO Rotatif')
    return render(request, 'APP/esb_eso_rotatif_list.html', {'testeurs_esb_eso_rotatif': testeurs_esb_eso_rotatif})

def dashboard(request):
    return render (request,'APP/home.html')



def add_testeur(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        # Create and save the Testeur object
        testeur = Testeur(name=name, email=email)
        testeur.save()
        return redirect('list_testeurs')
    return render(request, 'APP/add_testeur.html')

''' def edit_testeur(request, testeur_id):
    testeur = Testeur.objects.get(id=testeur_id)
    if request.method == 'POST':
        # Update testeur with the new data
        testeur.name = request.POST.get('name')
        testeur.email = request.POST.get('email')
        testeur.save()
        return redirect('list_testeurs')  # Redirect to the list of testeurs after editing
    return render(request, 'APP/edit_testeur.html', {'testeur': testeur}) '''

def delete_testeur(request, testeur_id):
    testeur = Testeur.objects.get(id=testeur_id)
    testeur.delete()
    return redirect('list_testeurs')
def extraire_donnees_via_ftp(testeur, selected_date):
    try:
        # Connexion FTP

        # Construct the file path based on the selected date
        file_path_remote = f"{testeur.chemin}/{selected_date.year}/{selected_date.month:02d}/{selected_date.day:02d}.CSV"

        # Connexion FTP
        ftp = ftplib.FTP(testeur.host)
        print("Connexion FTP établie")

        if testeur.username and testeur.password:
            print(f"Nom d'utilisateur: {testeur.username}, Mot de passe: {testeur.password}")
            ftp.login(user=testeur.username, passwd=testeur.password)

        else:
            print("Aucun nom d'utilisateur ni mot de passe fourni. Connexion anonyme.")
            ftp.login()

        print("Connexion FTP réussie")

        # Obtention du nom de fichier depuis le chemin
        file_name = os.path.basename(file_path_remote)

        # Téléchargement du fichier CSV depuis le serveur FTP
        with open(file_name, 'wb') as fichier_local:
            ftp.retrbinary('RETR ' + file_path_remote, fichier_local.write)

        # Lecture du fichier CSV avec pandas en spécifiant le délimiteur ';' et l'encodage UTF-8
        df = pd.read_csv(file_name, delimiter=';', encoding='utf-8')
        try:
            # Convertir la colonne "Date" en format de date avec années complètes (%Y)
            df['Date'] = pd.to_datetime(df['Date'], format='%d/%m/%Y', errors='raise')  # Changement du format ici
        except ValueError:
            # Si la conversion échoue avec le format '%d/%m/%Y', essayez avec '%d/%m/%y'
            df['Date'] = pd.to_datetime(df['Date'], format='%d/%m/%y', errors='coerce')

        # Filtrer les lignes avec des valeurs de date non valides
        df = df.dropna(subset=['Date'])

        # Extraire l'heure de la colonne "Heure"
        df['Heure'] = pd.to_datetime(df['Heure'], format='%H:%M:%S').dt.hour

        # Data processing for graph 1 (FPY over time)
        # Calculer le FPY par tranche de deux heures
        fpy_by_two_hours = df.groupby(df['Heure'] // 2 * 2).apply(
            lambda x: (x[x['Code err'] == 0].shape[0] / len(x)) * 100)

        # Ajouter le dernier FPY s'il n'y a pas exactement deux heures à la fin
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


"""def detailtesteur(request, testeur_id):
    testeur = Testeur.objects.get(pk=testeur_id)  # Récupérer le testeur en fonction de l'ID
    # Ajoutez ici votre logique de traitement des données liées au testeur
    return render(request, 'APP/detailtesteur.html', {'testeur': testeur})
"""


from django.utils import timezone
"""def detailtesteur(request, testeur_id):
    testeur = get_object_or_404(Testeur, pk=testeur_id)
    selected_date = None
    current_date = timezone.now().date()

    if request.method == 'POST':
        selected_date_str = request.POST.get('selected_date')
        if selected_date_str:
            selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d')

        graph1, graph2, graph3, nb_pieces_bonnes_global, nb_pieces_mauvaises_global, nb_pieces_total_global, fpy_global = extraire_donnees_via_ftp(testeur, selected_date)

        if graph1 is None or graph2 is None or graph3 is None:
            erreur = "Une erreur s'est produite lors du traitement des données."
            return render(request, 'APP/detailtesteur.html', {'testeur': testeur, 'erreur': erreur, 'current_date': current_date})
        else:
            return render(request, 'APP/detailtesteur.html',
                          {'testeur': testeur, 'graph1_data': graph1, 'graph2_data': graph2, 'graph3_data': graph3,
                           'nb_pieces_bonnes_global': nb_pieces_bonnes_global,
                           'nb_pieces_mauvaises_global': nb_pieces_mauvaises_global,
                           'nb_pieces_total_global': nb_pieces_total_global,
                           'fpy_global': fpy_global,
                           'selected_date': selected_date,
                           'current_date': current_date})

    return render(request, 'APP/detailtesteur.html', {'testeur': testeur, 'selected_date': selected_date, 'current_date': current_date})
"""

from django.shortcuts import render
from .models import Testeur, IndicateurPerformance, InterfaceStatistique



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

        if graph1 and graph2 and graph3:
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
def admin_home(request):
    return render(request,'APP/admin_home.html')

def user_home(request):
    return render(request,'APP/user_home.html')

@login_required(login_url='login')
def user_logout(request):
    logout(request)
    return HttpResponseRedirect('/')

