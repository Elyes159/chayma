from  django.contrib import admin
from  django.urls import path, include
from . import views
urlpatterns = [
    path('', views.index, name="index"),
    path('', views.HomePage, name='home'),
    path('login/', views.loginView, name="login"),
    path('logout/', views.user_logout, name="logout"),
    
    path('register/', views.register, name="register"),
    path('admin_register/', views.root_signup, name="admin_register"),
    path('insert_user/', views.insertuser, name="insert_user"),
    path('listusers/', views.listusers, name="listusers"),
    path('users/', views.users, name="users"),
    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('edit_user/<int:user_id>/', views.edit_user, name='edit_user'),
    path('save_user_changes/<int:user_id>/', views.save_user_changes, name='save_user_changes'),
    path('inserttesteur/', views.inserttesteur, name='inserttesteur'),
    path('edit_testeur/<int:pk>/', views.edit_testeur, name='edit_testeur'),
    path('delete_testeur/<int:testeur_id>/', views.delete_testeur, name='delete_testeur'),
    path('list_testeurs/', views.list_testeurs, name="list_testeurs"),
    path('listeligne/', views.listeligne, name="listeligne"),
    path('S15.html/', views.S15, name="S15"),
    path('detailtesteur/<int:testeur_id>/',views.detailtesteur,name="detailtesteur"),
    path('detailtesteur/<int:testeur_id>/', views.detailtesteur, name='detailtesteur'),
    path('dashboard/',views.dashboard,name="dashboard"),
    path('admin_home/', views.admin_home, name="admin_home"),
    path('user_home/', views.user_home, name="user_home"),
    path('forgetpassword/', views.forget_password, name="forgetpassword"),
    path('extraire_donnees_via_ftp/',views.extraire_donnees_via_ftp,name="extraire_donnees_via_ftp"),

    path("approve/<int:pk>/", views.approuve_user, name="approuve_user"),
    path("deny/<int:pk>/", views.deny_user, name="deny_user"),


]
