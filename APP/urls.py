from  django.contrib import admin
from django.contrib.auth import views as auth_views
from  django.urls import path, include
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView # type: ignore
   

urlpatterns = [
    path('', views.index, name="index"),
    path('login/', views.loginView, name="login"),
    path('logout/', views.user_logout, name="logout"),
    
    path('register/', views.register, name="register"),
    path('admin_register/', views.root_signup, name="admin_register"),
    path('users/', views.users, name="users"),
    path('users_app/<email>/', views.get_users, name="users_app"),

    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('delete_user_app/<email>/', views.delete_user_app, name='delete_user_app'),



    path('inserttesteur/', views.inserttesteur, name='inserttesteur'),
    path('inserttesteur_app/<email>/', views.inserttesteur_app, name='inset_app'),

    path('edit_testeur/<int:pk>/', views.edit_testeur, name='edit_testeur'),
    path('edit_testeur_app/<str:email>/<int:pk>/', views.edit_testeur_app, name='edit_testeur_app'),

    path('delete_testeur/<int:testeur_id>/', views.delete_testeur, name='delete_testeur'),
    path('list_testeurs/', views.list_testeurs, name="list_testeurs"),
    path('list_testeurs_app/<email>/', views.list_testeurs_app, name="list_testeurs_app"),

    path('listeligne/', views.listeligne, name="listeligne"),
    path('S15.html/', views.S15, name="S15"),
    path('detailtesteur/<int:testeur_id>/',views.detailtesteur,name="detailtesteur"),

    path('dashboard/',views.dashboard,name="dashboard"),
    path('extraire_donnees_via_ftp/',views.extraire_donnees_via_ftp,name="extraire_donnees_via_ftp"),

    path("approve/<int:pk>/", views.approuve_user, name="approuve_user"),
    path("approve_app/<email>/", views.approuve_user_app, name="approuve_user_app"),

    path("deny/<int:pk>/", views.deny_user, name="deny_user"),
    path("profile/", views.Userprofile, name="Userprofile"),
    path("api/profile/<email>/", views.update_user_profile, name="uup"),
    path("api/profile_admin/<email>/", views.update_user_profile_admin, name="uupa"),


    path("modify_user/<int:pk>/", views.ModifyUser, name="ModifyUser"),
    path("adduser/", views.adduser, name="adduser"),
    path("adduser_app/<email>/", views.add_user_app, name="adduser"),

    path('reset_password/', auth_views.PasswordResetView.as_view(template_name='APP/registration/password_reset.html'), name='password_reset'),
    path('reset_password_done/', auth_views.PasswordResetDoneView.as_view(template_name='APP/registration/password_reset_done.html'), name='password_reset_done'),
    path('reset_confirm/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='APP/registration/password_reset_confirm.html'), name='password_reset_confirm'),
    path('password_reset_complete/', auth_views.PasswordResetCompleteView.as_view(template_name='APP/registration/password_reset_complete.html'), name='password_reset_complete'),
    
    
    
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),




]
