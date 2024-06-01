from rest_framework import serializers
from .models import models, CustomUser

class CustomUserSerialzers(serializers.ModelSerializer):
  class Meta:
    model= CustomUser
    fields= ['nom', 'email', 'prenom']
    extra_kwargs={'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        return user

    def update(self, instance, validated_data):
        if 'password' in validated_data:
            instance.set_password(validated_data['password'])
            instance.save()
            validated_data.pop('password')
        return super().update(instance, validated_data)