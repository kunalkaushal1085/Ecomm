from os import error
import os
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
from django.core.files.uploadedfile import SimpleUploadedFile
import jwt
from django.core.files.uploadedfile import SimpleUploadedFile
import jwt
from bson import ObjectId
from django.utils import timezone



# Create your tests here.


class RegisterTestCase(APITestCase):
    
    def setUp(self):
        # Clear the database before each test
        db_handle, client = get_db_handle()

        # db_handle.user_collection.delete_many({})
    def create_user(self):
        
        try:
            unique_email = f"ram@yopmail.com"
            # unique_email = f"admin{int(time.time())}@yopmail.com"
            _data = {
                "first_name":"ram",
                "last_name":"sharma",
                "email":unique_email,
                "password":"12345",
                "username":"ram",
                "role": "seller",
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
        
from django.urls import reverse
def get_admin_token(client, email, password):
    """
    Helper function to log in as an admin and retrieve the authentication token.
    Replace this with your actual login mechanism.
    """
    login_url = reverse('customer-login')  # Replace 'login' with your actual login URL name
    data = {'email': email, 'password': password}
    response = client.post(login_url, data, format='json')
    assert response.status_code == status.HTTP_200_OK # or whatever status your login returns
    return response.data['token']


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



        
from rest_framework.test import APITestCase, APIClient
#admin add category test case
# Ensure the correct reverse name and URL are used
from django.urls import reverse

class AdminAddCategory(APITestCase):
    def setUp(self):
        db_handle, client = get_db_handle()
        self.user_collection = db_handle.user_collection
        self.client = APIClient()
        try:
            self.admin_token = get_admin_token(self.client, 'admin@gmail.com', '12345')  # Get the admin token
        except Exception as e:
            print(f"Error during setUp: {e}")
            raise

    def test_add_category_success(self):
        """
        Test case to verify that an admin can successfully add a new category
        with multiple images.
        """
        login_url = '/api/customer-login'
        category_url = '/api/add-category'  # Replace with the actual URL for adding categories

        # Authenticate and get the admin token
        _data = {
            "email": 'admin@gmail.com',  # Using the valid admin email
            "password": "12345"
        }
        _response = self.client.post(login_url, data=_data, format='json')

        # Check if login was successful (status code 200)
        self.assertEqual(_response.status_code, status.HTTP_200_OK)

        # Assuming the response contains the token, extract it
        self.admin_token = _response.data.get('token')
        
        # Ensure the token is returned in the response
        self.assertIsNotNone(self.admin_token, "Token is missing in login response")
        
        # Prepare test data for category creation
        data = {
            'title': 'Diamond Jewelry',
            'short_description': 'A brief description for the new category.',
            'product_type': 'silver1',  # Ensure this is unique for the test
            'image': 'tiger.avif',
        }
        image_name = 'tiger.avif' 
        # Prepare image files (create dummy files)
        image_path = os.path.join(settings.MEDIA_ROOT, 'category_images', image_name)
        print(image_path)
        if not os.path.exists(image_path):
            self.fail(f"Test image not found at {image_path}")
        img = open(image_path, 'rb')
        files = {'image': img}

        # Update the 'data' dictionary with the files
        data.update(files)
        
        # Set the authorization header with the admin token
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')

        try:
            _response = self.client.post('/api/add-category', data, format='multipart')
            _data = _response.json()
            print(_data,'data')
            # Assertions
            self.assertEqual(_response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(_data['message'], "Category added successfully.")
            self.assertIn(_data['data']['title'],'Diamond Jewelry')
            self.assertIsInstance(_data['data']['image'], list)
            self.assertEqual(len(_data['data']['image']), 1)  # Check if all images are in response
        finally:
            img.close()
        

    def test_add_category_missing_fields(self):
        """
        Test case to verify that the API returns an error if the required fields are missing.
        """
        login_url = '/api/customer-login'
        category_url = '/api/add-category'
        _data = {
            "email": 'admin@gmail.com',  # Using the valid admin email
            "password": "12345"
        }
        _response = self.client.post(login_url, data=_data, format='json')

        # Check if login was successful (status code 200)
        self.assertEqual(_response.status_code, status.HTTP_200_OK)

        # Assuming the response contains the token, extract it
        self.admin_token = _response.data.get('token')
        
        # Ensure the token is returned in the response
        self.assertIsNotNone(self.admin_token, "Token is missing in login response")
        # Prepare test data with missing fields
        data = {
            'title': '',  # Empty title
            'short_description': 'this is image',
            'product_type': ''  # Empty product type
        }
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')
        # Make the API request
        response = self.client.post(category_url, data, format='json')
        # Assert the response status code
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Assert the error message for missing fields
        response_data = response.json()
        self.assertIn('error', response_data)
        self.assertEqual(response_data['error'], 'All fields are required.')


#get categories according to product type
class GetCategoriesByProductType(APITestCase):
    def setUp(self):
        self.client = APIClient()

    def test_get_categories_by_product_type(self):
        login_url = '/api/customer-login'
        url = '/api/get-category'
        _data = {
            "email": 'admin@gmail.com',  # Using the valid admin email
            "password": "12345"
        }
        _response = self.client.post(login_url, data=_data, format='json')

        # Check if login was successful (status code 200)
        self.assertEqual(_response.status_code, status.HTTP_200_OK)
        self.admin_token = _response.data.get('token')
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')
        response = self.client.post(url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        

class AddProductTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()
        login_url = '/api/customer-login'
        category_url = '/api/add-category'
        add_product_url = '/api/add-product'

        # Authenticate and get the admin token
        admin_data = {
            "email": 'admin@gmail.com',  # Using the valid admin email
            "password": "12345"
        }
        _response = self.client.post(login_url, data=admin_data, format='json')

        # Check if login was successful (status code 200)
        self.assertEqual(_response.status_code, status.HTTP_200_OK)
        self.admin_token = _response.data.get('token')
        print(self.admin_token,'self.admin_token')
        self.assertIsNotNone(self.admin_token, "Admin token is missing in login response")
        
        # Seller login and token retrieval
        seller_data = {
            "email": 'ram@yopmail.com',
            "password": "123456"
        }
        seller_response = self.client.post(login_url, data=seller_data, format='json')
        print(seller_response.status_code,'seller_response++++++++++++++++')
        self.assertEqual(seller_response.status_code, status.HTTP_200_OK)
        self.seller_token = seller_response.data.get('token')
        self.assertIsNotNone(self.seller_token, "Seller token is missing in login response")
    
        
    def test_admin_can_add_product(self):
        """Test that an admin can successfully add a product"""
        login_url = '/api/customer-login'
        add_product_url = '/api/add-product'
        admin_data = {
            "email": 'admin@gmail.com',  # Using the valid admin email
            "password": "12345"
        }
        _response = self.client.post(login_url, data=admin_data, format='json')
        print(_response,'response inside test')
        self.admin_token = _response.data.get('token')
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')

        product_data = {
            'name': 'Test Product',
            # 'featured_image': featured_image_url,
            'short_description': 'This is a test product',
            'discount_price': '90',
            'discount_percentage': '10',
            'price': '100',
            'tag': 'electronics,gadgets',
            'sizes': 'M,L,XL',
            'colors': 'Red,Blue',
            'category_id': str(ObjectId()),  # Mock category ID
            'sku': 'SKU-12345',
        }
        image_name = 'pexels-photo-1519088.jpeg'
        # Prepare image files (create dummy files)
        image_path = os.path.join(settings.MEDIA_ROOT, 'gallery_images', image_name)
        print(image_path)
        if not os.path.exists(image_path):
            self.fail(f"Test image not found at {image_path}")
        img = open(image_path, 'rb')
        files = {'image': img}

        # Update the 'data' dictionary with the files
        product_data.update(files)
        response = self.client.post('/api/add-product', product_data, format='multipart')
        _data = response.json()
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(_data['message'], "Product added successfully")
    
    def test_add_product_missing_fields(self):
        """Test adding a product with missing required fields"""
        data = {
            'name': '', 
            'short_description': 'This is a test description',
            'price': '',
            'discount_percentage': '',
            'discount_price': '',
            'tag': '',
            'sizes': '',
            'colors': '',
            'category_id': self.category_id,
            'sku': '',
        }
        response = self.client.post(self.add_product_url, data, format='json')
        print(response,'response')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)



#admin can get user list
class GetUserListTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()
        login_url = '/api/customer-login'

        # Authenticate and get the admin token
        admin_data = {
            "email": 'admin@gmail.com',  # Using the valid admin email
            "password": "12345"
        }
        _response = self.client.post(login_url, data=admin_data, format='json')

        # Check if login was successful (status code 200)
        self.assertEqual(_response.status_code, status.HTTP_200_OK)
        self.admin_token = _response.data.get('token')
        self.assertIsNotNone(self.admin_token, "Admin token is missing in login response")

        # Seller login and token retrieval
        seller_data = {
            "email": 'ram@yopmail.com',
            "password": "123456"
        }
        seller_response = self.client.post(login_url, data=seller_data, format='json')

        # Check if seller login is successful
        self.assertEqual(seller_response.status_code, status.HTTP_200_OK)
        self.seller_token = seller_response.data.get('token')
        self.assertIsNotNone(self.seller_token, "Seller token is missing in login response")

        # Buyer login and token retrieval
        buyer_data = {
            "email": 'shyam@yopmail.com',
            "password": "12345"
        }
        buyer_response = self.client.post(login_url, data=buyer_data, format='json')
        # Check if buyer login is successful
        self.assertEqual(buyer_response.status_code, status.HTTP_200_OK)
        self.buyer_token = buyer_response.data.get('token')
        self.assertIsNotNone(self.buyer_token, "Buyer token is missing in login response")

    def test_admin_get_user_list(self):
        """Test that an admin can successfully fetch user list"""
        get_user_list_url = '/api/get-user-list'  # Adjust this to your actual endpoint
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')

        response = self.client.post(get_user_list_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('data', response.data)
        self.assertIn('buyers', response.data)
        self.assertIn('message', response.data)
        self.assertEqual(response.data['message'], "Users fetched successfully.")

    def test_seller_get_user_list(self):
        """Test that a seller can only fetch their own information"""
        get_user_list_url = '/api/get-user-list'  # Adjust this to your actual endpoint
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.seller_token}')

        response = self.client.post(get_user_list_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('data', response.data)
        self.assertIn('buyers', response.data)
        self.assertEqual(len(response.data['data']), 1)  # Only the seller's info
        self.assertEqual(response.data['buyers'], [])

    def test_buyer_get_user_list(self):
        """Test that a buyer can only fetch their own information"""
        get_user_list_url = '/api/get-user-list'  # Adjust this to your actual endpoint
        self.client.credentials(HTTP_AUTHORIZATION=f' {self.buyer_token}')

        response = self.client.post(get_user_list_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('data', response.data)
        self.assertIn('buyers', response.data)
        self.assertEqual(len(response.data['buyers']), 1)  # Only the buyer's info
        self.assertEqual(response.data['data'], [])

    def test_invalid_token(self):
        """Test the case where an invalid token is used"""
        get_user_list_url = '/api/get-user-list'  # Adjust this to your actual endpoint
        self.client.credentials(HTTP_AUTHORIZATION='Token invalid_token')

        response = self.client.post(get_user_list_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Please login again or check the token.')

    def test_user_not_found(self):
        """Test the case where the seller ID is not found"""
        get_user_list_url = '/api/get-user-list'  # Adjust this to your actual endpoint
        invalid_token = 'Bearer invalid_user_token'  # Use an invalid token to simulate this scenario
        self.client.credentials(HTTP_AUTHORIZATION=invalid_token)

        response = self.client.post(get_user_list_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'User not found.')


#Admin can get all product list and seller get own product list
class GetAllProductListTestCase(APITestCase):

    def setUp(self):
        """Set up the test environment and create test users."""
        self.client = APIClient()
        login_url = '/api/customer-login'

        # Authenticate and get the admin token
        admin_data = {
            "email": 'admin@gmail.com',  # Using the valid admin email
            "password": "12345"
        }
        _response = self.client.post(login_url, data=admin_data, format='json')

        # Check if login was successful (status code 200)
        self.assertEqual(_response.status_code, status.HTTP_200_OK)
        self.admin_token = _response.data.get('token')
        self.seller_token = _response.data.get('token')
        self.assertIsNotNone(self.admin_token, "Admin token is missing in login response")
        self.assertIsNotNone(self.seller_token, "Seller token is missing in login response")

        # Seller login and token retrieval
        seller_data = {
            "email": 'ram@yopmail.com',
            "password": "123456"
        }
        seller_response = self.client.post(login_url, data=seller_data, format='json')
        print(seller_response.data,'seller response')
        # Check if seller login is successful
        self.assertEqual(seller_response.status_code, status.HTTP_200_OK)
        self.seller_token = seller_response.data.get('token')
        self.assertIsNotNone(self.seller_token, "Seller token is missing in login response")

        # Buyer login and token retrieval
        # buyer_data = {
        #     "email": 'shyam@yopmail.com',
        #     "password": "12345"
        # }
        # buyer_response = self.client.post(login_url, data=buyer_data, format='json')
        # # Check if buyer login is successful
        # self.assertEqual(buyer_response.status_code, status.HTTP_200_OK)
        # self.buyer_token = buyer_response.data.get('token')
        # self.assertIsNotNone(self.buyer_token, "Buyer token is missing in login response")

        # Create products in the database for testing
        self.product_data_1 = {
            "name": "Product A",
            "price": 100,
            "sellert_id": '67ac929d42c14b9853f2655e',  # Simulating seller ID
            "category_id": "677630ae44caa07cb62b01b2",
        }
        self.product_data_2 = {
            "name": "Product B",
            "price": 200,
            "sellert_id": '67ac929d42c14b9853f2655e',  # Another seller ID
            "category_id": "677630ae44caa07cb62b01b2",
        }

        # Save products to the database via the product creation API (this assumes a URL exists for product creation)
        self.client.post('/api/add-product', self.product_data_1, format='json')
        self.client.post('/api/add-product', self.product_data_2, format='json')
    def test_admin_can_get_all_products(self):
        """Test that admin can get the list of all products."""
        get_product_list_url = '/api/get-all-product-list'  # The endpoint to fetch all products
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.admin_token}')

        response = self.client.post(get_product_list_url, format='json')
        # print(response.json(),'check response in test_admin_can_get_all_products ')
        # Assert that the status code is OK and products are returned
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('status'),'success')
        self.assertIn('products', response.data)
        self.assertEqual(len(response.data['products']), 2)  # Since we added 2 products in setup
    
    def test_seller_can_get_their_own_products(self):
        """Test that seller can only see their own products."""
        get_product_list_url = '/api/get-all-product-list'  # The endpoint to fetch the seller's products
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.seller_token}')
        # Test the API endpoint for getting seller's products
        response = self.client.post(get_product_list_url, format='json')
        print(response.json())
        # Assert that the status code is OK and seller sees only their own product
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('products', response.data)
        self.assertEqual(len(response.data['products']), 4)  # Only 1 product should be returned for the seller

    def test_no_products_found(self):
        """Test that the API returns 404 when no products are found for a seller and 200 if products exist."""

        self.client = APIClient()
        login_url = '/api/customer-login'
        
        # Simulate a seller with no products
        seller_data = {
            "email": 'ram@yopmail.com',
            "password": "123456"
        }

        # Log in the seller
        seller_response = self.client.post(login_url, data=seller_data, format='json')
        self.assertEqual(seller_response.status_code, status.HTTP_200_OK)
        seller_token = seller_response.data.get('token')
        self.assertIsNotNone(seller_token)  # Ensure token is retrieved

        # Set token for authentication
        self.client.credentials(HTTP_AUTHORIZATION=f'{seller_token}')

        # Fetch products
        response = self.client.post('/api/get-all-product-list', format='json')

        if response.status_code == status.HTTP_200_OK:
            self.assertIn('products', response.data)
            self.assertGreater(len(response.data['products']), 0, "Products should be present.")
            print("✅ Products found:", response.data['products'])
        elif response.status_code == status.HTTP_404_NOT_FOUND:
            self.assertIn('error', response.data)
            self.assertEqual(response.data['error'], 'No products found.')
            print("⚠️ No products found.")
        else:
            self.fail(f"❌ Unexpected response status: {response.status_code}")


    def test_invalid_token(self):
        """Test that an invalid token returns a 403 error."""
        invalid_token = 'invalid_token'
        self.client.credentials(HTTP_AUTHORIZATION=f' {invalid_token}')
        
        response = self.client.post('/api/get-all-product-list', format='json')

        # Assert the response status code and error message
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Please login again or check the token.')

    def test_error_handling(self):
        """Test that errors are handled gracefully (simulate a database error)."""
        self.client.credentials(HTTP_AUTHORIZATION=f'{self.seller_token}')
        
        # Force a database error or invalid query (this is simulated for testing purposes)
        with self.assertRaises(Exception):
            response = self.client.post('/api/get-all-product-list', format='json')

        # Assert the error response
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], 'Error retrieving product list: Database error')