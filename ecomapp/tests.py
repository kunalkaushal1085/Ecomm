from os import error
import stat
from django.test import TestCase
from rest_framework.test import APITestCase
from rest_framework import status
from ecomapp.db_connection import get_db_handle
from rest_framework.response import Response
import time
from unittest.mock import patch
import bcrypt
from datetime import datetime, timedelta
from django.conf import settings
from django.core.mail import send_mail
from django.test.utils import override_settings

# Create your tests here.


class RegisterTestCase(APITestCase):
    
    def setUp(self):
        # Clear the database before each test
        db_handle, client = get_db_handle()

        # db_handle.user_collection.delete_many({})
    def create_user(self):
        
        try:
            unique_email = f"admin{int(time.time())}@yopmail.com"
            _data = {
                "first_name":"admin",
                "last_name":"admin",
                "email":unique_email,
                "password":"12345",
                "username":"admin",
                "role": "admin",
                "phone_number": "1234567890",
                "address": [
                    {
                    "street": "123 Main St",
                    "city": "Springfield",
                    "state": "IL",
                    "country": "USA",
                    "zipcode": "62701"
                    }
                ]
                }
            _response = self.client.post('/api/customer-register', data = _data, format='json')
            print(_response.status_code,'response')
            _data = _response.json()
            self.assertEqual(_data.status_code, status.HTTP_201_CREATED)
            self.assertEqual(_data['data']['email'], unique_email)
            self.assertEqual(_data['message'], "User registered successfully.")
            self.assertEqual(_data['data']['status'], "pending")
            self.assertEqual(_data['data']['first_name'], "John")
            self.assertEqual(_data['data']['last_name'], "Doe")
            self.assertEqual(_data['data']['role'], "seller")
            
        except Exception as e:
            print(e)


    def required_fields(self):
        try:
            # Using data with missing fields (empty email, password, etc.)
            unique_email = f"john{int(time.time())}@gmail.com"
            _data = {
                "first_name": "",
                "last_name": "",
                "email": "",
                "password": "",
                "username": "",
                "role":"",
                "phone_number":""
            }

            # Send POST request to register
            _response = self.client.post('/api/customer-register', data=_data, format='json')
            print(_response.status_code, 'response')
            
            # Get the response data
            _data = _response.json()
            
            if _data:
                self.assertEqual(_response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertEqual(_data,status.HTTP_400_BAD_REQUEST)
                print("Response body:", _data)

        except Exception as e:
            print(e)
    

    def email_already_exists(self):
        try:
            db_handle, client = get_db_handle()
            
            # First, register a user with a unique email
            unique_email = f"john{int(time.time())}@gmail.com"
            _data = {
                "first_name": "john",
                "last_name": "doe",
                "email": unique_email,
                "password": "12345",
                "username": "john123"
            }
            
            # Register the first user
            _response = self.client.post('/api/customer-register', data=_data, format='json')
            print(_response.status_code, 'response')
            _data = _response.json()
            print("First response data:", _data)

            # Now try to register a second user with the same email
            _data_second = {
                "first_name": "jane",
                "last_name": "doe",
                "email": unique_email,
                "password": "12345",
                "username": "jane123"
            }

            # Attempt registration with the duplicate email
            _response_second = self.client.post('/api/customer-register', data=_data_second, format='json')
            print(_response_second.status_code, 'response')

            # Get the response data for the second request
            _data_second = _response_second.json()

            # Check if the response is indicating an error for the duplicate email
            print("Second response data:", _data_second)
            self.assertEqual(_response_second.status_code, status.HTTP_400_BAD_REQUEST)

            # Check if the error message indicates the email already exists
            self.assertIn("error", _data_second)
            self.assertEqual(_data_second['error'], "User with this email already exists.")
            
            # Optional: Confirm that the email exists in the database (no need to insert it again)
            user_collection = db_handle.user_collection
            existing_user = user_collection.find_one({"email": unique_email})
            self.assertIsNotNone(existing_user)  # Ensure the user exists in the DB

        except Exception as e:
            print(e)


class LoginTest(APITestCase):   
    def setUp(self):
        db_handle, client = get_db_handle()
        user_collection = db_handle.user_collection
        # Create a user for testing login
        self.unique_email = f"john{int(time.time())}@yopmail.com"
        password = "12345"
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        user_collection.insert_one({
            "first_name": "john",
            "last_name": "doe",
            "email": self.unique_email,
            "password": hashed_password,
            "username": "john123",
            "role": "seller",
            "status": "pending",
        })
        self.invalid_email = "test@gmail.com"
        self.invalid_password = "123456"
        
    def user_login(self):
        _data = {
            "email": self.unique_email,
            "password": "12345"
        }
        _response = self.client.post('/api/customer-login', data=_data, format='json')
        _data = _response.json()
        self.assertEqual(_response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(_data['status'], status.HTTP_403_FORBIDDEN)
        self.assertEqual(_data['message'], 'Your account is pending approval by the admin. You cannot log in yet.')
        # self.assertEqual(_data['user'], _data['user'])
        # self.assertEqual(_data['base_url'], _data['base_url'])
        print("Response body:", _data,status.HTTP_200_OK)

    def invalid_email(self):
        _data = {
            "email": self.invalid_email,  # Using the invalid email
            "password": "12345"
        }
        _response = self.client.post('/api/customer-login', data=_data, format='json')
        _data = _response.json()

        # Assert that the response is for an invalid email
        self.assertEqual(_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(_data['status'], status.HTTP_400_BAD_REQUEST)
        self.assertEqual(_data['message'], 'Invalid email')
        print("Invalid email login response:", _data)
        
    def invalid_password(self):
        _data = {
            "email": self.unique_email, 
            "password": self.invalid_password
        }
        _response = self.client.post('/api/customer-login', data=_data, format='json')
        _data = _response.json()

        # Assert that the response is for an invalid email
        self.assertEqual(_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(_data['status'], status.HTTP_400_BAD_REQUEST)
        self.assertEqual(_data['message'], 'Invalid password')
        print("Invalid email login response:", _data)
    
from bson import ObjectId
#admin approve test case
class AdminApproveSellerTest(APITestCase):
    
    def setup(self):
        self.seller_id = "6773e332e3cc0d331271c329"
        self.status_value = 'pending'
        db_handle, client = get_db_handle()
        user_collection = db_handle.user_collection
        password = "12345"
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.unique_email = f"john{int(time.time())}@yopmail.com"
        user_collection.insert_one({
            "first_name": "john",
            "last_name": "doe",
            "email": self.unique_email,
            "password": hashed_password,
            "username": "john123",
            "role": "seller",
            "status": "pending",
        })
        print(f"Seller ID: {self.seller_id}")
        
        
    @override_settings(EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend')
    def test_approve_seller_and_login(self):
        print('Testing approve seller...')
        # print(f"Accessing seller_id: {self.seller_id}")  # Print to check if seller_id is accessible
        _data = {
            "seller_id": str('6773e332e3cc0d331271c329'),  # Correct key 'seller_id'
            "status": 'approve'
        }
        response = self.client.post('/api/approved-seller', data=_data, format='json')
        response_data = response.json()
        print('response_data',response_data)
        print('approve_data', response_data['status'])
        # Assert the response
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response_data['message'], 'Seller account approved and email sent.')
        self.assertEqual(response_data['status'], status.HTTP_200_OK)
        
        
    @override_settings(EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend')
    def test_decline_seller_and_login(self):
        print('Testing decline seller...')

        _data = {
            "seller_id": str('6773e332e3cc0d331271c329'),
            "status": 'decline'
        }
        response = self.client.post('/api/approved-seller', data=_data, format='json')
        response_data = response.json()
        print('response_data',response_data)
        print('decline', response_data['status'])
        # Assert the response
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response_data['message'], 'Seller account declined and email sent.')
        self.assertEqual(response_data['status'], status.HTTP_200_OK)
        

class PasswordResetRequestTest(APITestCase):
    def setUp(self):
        db_handle, client = get_db_handle()
        user_collection = db_handle.user_collection
        self.existing_email = "john1734675033@yopmail.com"
        self.invalid_email = "test@gmail.com"
        user = user_collection.find_one({"email": self.existing_email.lower()})
        if not user:
            password = "12345"
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user_collection.insert_one({
                "first_name": "john",
                "last_name": "doe",
                "email": self.existing_email,
                "password": hashed_password,
                "username": "john123"
            })

    
    def password_reset(self):
        # Test for valid email for password reset
        _data = {"email": self.existing_email}
        _response = self.client.post('/api/forgot-password', data=_data, format='json')
        _data = _response.json()
        # Check the response for valid email
        self.assertEqual(_response.status_code, status.HTTP_200_OK)
        self.assertEqual(_data['message'], 'Password reset link sent successfully.')
        print("Valid password reset response:", _data)
        
    def invalid_email(self):
        # Test for invalid email (email not registered)
        _data = {"email": self.invalid_email}
        _response = self.client.post('/api/forgot-password', data=_data, format='json')
        _data = _response.json()

        # Assert that the response indicates no user found for the given email
        self.assertEqual(_response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(_data['error'], 'No user found with this email.')
        print("Invalid email password reset response:", _data)
        
    
    @override_settings(EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend')
    def email_sent(self):
        _data = {"email": self.existing_email}
        _response = self.client.post('/api/forgot-password', data=_data, format='json')
        _data = _response.json()
        # Check the response
        self.assertEqual(_response.status_code, status.HTTP_200_OK)
        self.assertEqual(_data['message'], 'Password reset link sent successfully.')
        print("response body:", _data,status.HTTP_200_OK)
        

class PasswordResetConfirmTest(APITestCase):
    def setUp(self):
        # Set up MongoDB collections and mock data
        self.token = "dfc6ba73afcb461f8d48861be18172b5" #add token here
        self.new_password = "123456789"
        self.invalid_token = "81b0443cbe4545b1a504701575b94aa2s"
        self.expired_token = "81b0443cbe4545b1a504701575b94aa2s"
        db_handle, client = get_db_handle()
        reset_token_collection = db_handle.reset_token_collection
        self.user_collection = db_handle.user_collection
        token_record = reset_token_collection.find_one({"token": self.token})
    
    def test_invalid_token(self):
        # Test with an invalid token
        url = '/api/reset-password'
        data = {
            'token': self.invalid_token,
            'new_password': self.new_password,
            'confirm_password': self.new_password
        }
        # Send the request to reset the password with an invalid token
        response = self.client.post(url, data, format='json')
        _data =response.json()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(_data['message'], 'Invalid or expired token.')
        print("Invalid token response:", _data)
        
    def test_expired_token(self):
        # Test with an expired token
        url = '/api/reset-password'
        data = {
            'token': self.expired_token,
            'new_password': self.new_password,
            'confirm_password': self.new_password
        }
        # Send the request to reset the password with an expired token
        response = self.client.post(url, data, format='json')
        _data = response.json()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(_data['message'], 'Invalid or expired token.')
        print("Expired token response:", _data)
        
    def token_is_valid(self):
        # Test with a valid token
        url = '/api/reset-password'
        data = {
            'token': self.token,
            'new_password': self.new_password,
            'confirm_password': self.new_password
        }
        # Send the request to reset the password with a valid token
        response = self.client.post(url, data, format='json')
        _data = response.json()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(_data['message'], 'Password has been reset successfully.')
        print("Valid token response:", _data)


