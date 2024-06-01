from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser, Testeur

class SignupForm(UserCreationForm):
    class Meta():
        model = CustomUser
        fields = ['prenom','nom','email','password1', 'password2']

    def __init__(self, *args, **kwargs):
        super(SignupForm, self).__init__(*args, **kwargs)
        # Applying CSS classes to the fields
        self.fields['email'].widget.attrs.update({'type': 'email', 'class': 'form-control', 'placeholder':'Email'})
        self.fields['prenom'].widget.attrs.update({'class': 'form-control', 'placeholder':'Prenom','autofocus': 'autofocus'})
        self.fields['nom'].widget.attrs.update({'class': 'form-control', 'placeholder':'Nom'})
        self.fields['password1'].widget.attrs.update({'class': 'form-control', 'placeholder':'Mots de passe'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control', 'placeholder':'Confirmez le mot de passe'})

        self.fields['email'].label = "Adresse Email"
        self.fields['prenom'].label = "Prenom"
        self.fields['nom'].label = "Nom"
        self.fields['password1'].label = "Mots de passe"
        self.fields['password2'].label = "Confirmez le mot de passe"

    def clean_email(self):
        email = self.cleaned_data['email']
        if CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError("Cette adresse email est déjà utilisée.")
        return email

class rootForm(UserCreationForm):
    class Meta():
        model = CustomUser
        fields = ['prenom','nom','email','password1', 'password2']

    def __init__(self, *args, **kwargs):
        super(rootForm, self).__init__(*args, **kwargs)
        # Applying CSS classes to the fields        
        self.fields['prenom'].widget.attrs.update({'class': 'form-control', 'placeholder':'Prenom', 'autofocus': 'autofocus'})
        self.fields['nom'].widget.attrs.update({'class': 'form-control', 'placeholder':'Nom'})
        self.fields['email'].widget.attrs.update({'class': 'form-control', 'placeholder':'Email'})
        self.fields['password1'].widget.attrs.update({'class': 'form-control', 'placeholder':'Mots de passe'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control', 'placeholder':'Confirmez le mot de passe'})

    def save(self, commit=True):
        user = super(rootForm, self).save(commit=False)
        user.is_admin = True
        user.is_active = True
        if commit:
            user.save()
        return user

class TesteurForm(forms.ModelForm):
    class Meta:
        model = Testeur
        fields = ['name', 'ligne', 'password', 'host', 'chemin']
    
    def __init__(self, *args, **kwargs):
        super(TesteurForm, self).__init__(*args, **kwargs)
        # Applying CSS classes to the fields        
        self.fields['name'].widget.attrs.update({'class': 'form-control', 'placeholder':'name', 'autofocus': 'autofocus'})
        self.fields['ligne'].widget.attrs.update({'class': 'form-control', 'placeholder':'ligne'})
        self.fields['password'].widget.attrs.update({'class': 'form-control', 'placeholder':'password'})
        self.fields['host'].widget.attrs.update({'class': 'form-control', 'placeholder':'host'})
        self.fields['chemin'].widget.attrs.update({'class': 'form-control', 'placeholder':'chemin'})


class updateProfileForm(forms.ModelForm):
    class Meta():
        model = CustomUser
        fields = ['prenom','nom','email']
    def __init__(self, *args, **kwargs):
        super(updateProfileForm, self).__init__(*args, **kwargs)
        # Applying CSS classes to the fields
        self.fields['email'].widget.attrs.update({'type': 'email', 'class': 'form-control', 'placeholder':'Email'})
        self.fields['prenom'].widget.attrs.update({'class': 'form-control', 'placeholder':'Prenom'})
        self.fields['nom'].widget.attrs.update({'class': 'form-control', 'placeholder':'Nom'})
        self.fields['email'].label = "Adresse Email"