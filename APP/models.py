from django.db import models
from django.contrib.auth.models import AbstractUser, AbstractBaseUser, BaseUserManager, PermissionsMixin

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(username=username.strip(), email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,
    )
    nom=models.CharField(max_length=100,null=True)
    prenom=models.CharField(max_length=100,null=True)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    USERNAME_FIELD = 'email'
    
    @property
    def is_staff(self):
        return self.is_admin

    objects = CustomUserManager()

''' class CustomUser(AbstractUser):

    is_active = models.BooleanField(default=False)

    # Ajout des related_name pour éviter les conflits
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_set',
        blank=True,
        verbose_name='groups',
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
    )


    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_set',
        blank=True,
        verbose_name='user permissions',
        help_text='Specific permissions for this user.',
    )

    def __str__(self):
        return self.username '''

class Testeur(models.Model):
    name = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    ligne = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    host = models.CharField(max_length=100)
    chemin = models.CharField(max_length=100, default='')

    class Meta:
        db_table = 'testeur'

    def __str__(self):
        return self.username

class IndicateurPerformance(models.Model):
    testeur = models.ForeignKey(Testeur, on_delete=models.CASCADE)
    fpy = models.FloatField()
    pieces_bonnes = models.IntegerField()
    pieces_total = models.IntegerField()
    pieces_mauvaises = models.IntegerField()
    top_defaut = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.testeur} - {self.top_defaut}"

class InterfaceStatistique(models.Model):
    interface = models.CharField(max_length=100)
    fpy_interface = models.FloatField()
    pieces_bonnes_interface = models.IntegerField()
    pieces_mauvaises_interface = models.IntegerField()
    pieces_total_interface = models.IntegerField()
    top_defaut_interface = models.CharField(max_length=100, default="")

    def __str__(self):
        return (f"Interface: {self.interface}, FPY: {self.fpy_interface}, "
                f"Pièces bonnes: {self.pieces_bonnes_interface}, Pièces mauvaises: {self.pieces_mauvaises_interface}, "
                f"Pièces total: {self.pieces_total_interface}, Top défaut: {self.top_defaut_interface}")
