from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.response import Response
import logging
from rest_framework.permissions import IsAuthenticated

logger = logging.getLogger(__name__)



class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data
    
class AddressSerializer(serializers.Serializer):
    street = serializers.CharField(max_length=255)
    city = serializers.CharField(max_length=255)
    state = serializers.CharField(max_length=255)
    country = serializers.CharField(max_length=255)
    zipcode = serializers.CharField(max_length=10)
    
class UserDetailsSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=15)
    address = AddressSerializer(many=True)  # This allows an array of address dictionaries
    role = serializers.CharField(max_length=50)