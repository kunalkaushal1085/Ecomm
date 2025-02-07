from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from django.core.mail import send_mail
import bcrypt
from datetime import datetime, timedelta, timezone
import uuid
from .db_connection import get_db_handle
import os
from .serializers import *
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken
import jwt
from . db_connection import Database
from django.conf import settings
from pathlib import Path



# Create your views here.

class UserRegistrationView(APIView):
    def post(self, request):
        data = request.data
        email = data.get('email')
        password = data.get('password')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        username = data.get('username')
        role = data.get('role')
        phone_number = data.get('phone_number')
        address = data.get('address')

        # if not email or not password or not first_name or not last_name or not username:
        if not email or not password or not first_name or not last_name or not username or not role or not phone_number:
            return Response({"error": "Missing required fields."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate `role` value
        if role not in ['seller', 'buyer','admin']:
            return Response({"message": "Role must be 'seller' or 'buyer' or 'admin'."})
        db_handle, _ = get_db_handle()  # Get the MongoDB database handle
        super_admin_exists = Database.FindOne(db_handle, Database.USER_COLLECTION, {"role": "admin"})
        if role == 'admin' and super_admin_exists:
            return Response({"error": "Admin has already been created."}, status=status.HTTP_400_BAD_REQUEST)
        if Database.FindOne(db_handle, Database.USER_COLLECTION, {"email": email}):
            return Response({"status": status.HTTP_400_BAD_REQUEST,"error": "User with this email already exists."})
        user_id = str(uuid.uuid4())
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        if role == "admin" and not super_admin_exists:
            status_value  = True  # First admin will be set to True
        elif role == "seller":
            status_value  = "pending"
        else:
            status_value  = False
        user_data = {
            "user_id": user_id,
            "email": email,
            "password": hashed_password,
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
            "role": role,
            "phone_number": phone_number,
            "address": address,
            "status": status_value ,
            "created_at": datetime.utcnow().isoformat(), 
            "updated_at": datetime.utcnow().isoformat()
        }
        try:
            inserted_id = Database.InsertData(db_handle, Database.USER_COLLECTION, user_data)
            user_data['_id'] = str(inserted_id)
            return Response({
                "status": status.HTTP_201_CREATED,
                "message": "User registered successfully.",
                "data": user_data
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLoginView(APIView):
    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')

            if not email or not password:
                return Response({'error': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

            db_handle, _ = get_db_handle()  # Get the MongoDB database handle
            user_collection = db_handle.user_collection

            # Find the user by email
            user = user_collection.find_one({
                "$or": [
                    {"email": email.lower()},
                    {"username": email}
                ]
            })
            print(user,'???')
            if user:
                if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                    print(">>>>>>>>>",user.get('status'))
                    if user['role'] == 'seller' and user.get('status') == 'pending':
                        print('insdie role')
                        return Response({
                            'status': status.HTTP_403_FORBIDDEN,
                            'message': 'Your account is pending approval by the admin. You cannot log in yet.'
                        }, status=status.HTTP_403_FORBIDDEN)
                    payload = {
                        'user_id': str(user['_id']),  # Convert _id to string
                        'email': user['email'],
                        'username': user['username'],
                        'exp': datetime.utcnow() + timedelta(days=1),  # Token expiry (1 hour)
                        'iat': datetime.utcnow()  # Issued at time
                        
                    }
                    secret_key = os.getenv('JWT_SECRET_KEY', os.getenv('SECRET_KEY'))
                    access_token = jwt.encode(payload, secret_key, algorithm='HS256')
                    user_data = {
                        "_id": str(user['_id']),  # Ensure _id is a string
                        "email": user['email'],
                        "first_name": user['first_name'],
                        "last_name": user['last_name'],
                        "role": user['role'],
                        "username": user['username']
                    }
                    return Response({
                        'status': status.HTTP_200_OK,
                        'message': 'User logged in successfully',
                        'token': access_token,
                        'user': user_data,
                        'base_url': os.getenv("FRONTEND_URL")
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'status': status.HTTP_400_BAD_REQUEST,
                        'message': 'Invalid password'
                    }, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({
                    'status': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid email'
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e: 
            print(str(e),"error")
            return Response({
                'status': status.HTTP_400_BAD_REQUEST,'message':str(e)},status=status.HTTP_400_BAD_REQUEST)

# Admin API to approve seller accounts
class AdminApproveSellerView(APIView):
    def post(self, request):
        try:
            seller_id = request.data.get('seller_id')
            status_value = request.data.get('status') 
            if not seller_id:
                return Response({'error': 'Seller ID is required.'}, status=status.HTTP_400_BAD_REQUEST)
            if status_value.lower() not in ['approve', 'decline']:
                return Response({'error': 'Invalid status. It should be either "approve" or "decline".'}, status=status.HTTP_400_BAD_REQUEST)
            status_value = status_value.title()

            db_handle, _ = get_db_handle()

            # Find the seller by ID
            seller = Database.FindOne(db_handle, Database.USER_COLLECTION, {"_id": ObjectId(seller_id), "role": "seller"})
            if not seller:
                return Response({'error': 'Seller not found.'}, status=status.HTTP_404_NOT_FOUND)
            user_data = {
                'status': status_value,
                
            }
            if status_value:
                update_result = Database.Update(db_handle, Database.USER_COLLECTION, {"_id": ObjectId(seller_id)}, user_data)
                if update_result.matched_count == 0:
                    return Response({'error': 'Product update failed.'}, status=status.HTTP_404_NOT_FOUND)
                # Send approval email to the seller
                subject = f"Your account has been {status_value}!"
                message = f"Hello {seller.get('first_name', 'User')},\n\nYour account has been {status_value} by the admin. You can now log in to your account.\n\nBest regards,\nThe Team"
                from_email = settings.EMAIL_HOST_USER  
                recipient_list = [seller['email']]

                send_mail(
                    subject,
                    message,
                    from_email,
                    recipient_list,
                    fail_silently=False
                )

                return Response({
                    'status': status.HTTP_200_OK,
                    'message': f'Seller account {status_value} and email sent.'
                }, status=status.HTTP_200_OK)

            else:
                return Response({
                    'status': status.HTTP_200_OK,
                    'message': 'Seller Unavailable and try after some time.'
                }, status=status.HTTP_200_OK)

        except Exception as e:
            print(str(e), "error")
            return Response({
                'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        db_handle, _ = get_db_handle()
        user_collection = db_handle.user_collection
        reset_token_collection = db_handle.reset_token_collection

        # Find the user by email
        user = user_collection.find_one({"email": email.lower()})

        if not user:
            return Response({'error': 'No user found with this email.'}, status=status.HTTP_404_NOT_FOUND)
        token = uuid.uuid4().hex
        expiry_time = datetime.now(timezone.utc) + timedelta(hours=1)

        # Store token and expiry in the database
        reset_token_collection.update_one(
            {"user_id": user['_id']},
            {"$set": {"token": token, "expiry": expiry_time}},
            upsert=True
        )
        # Construct reset URL
        reset_url = f"{os.getenv("FRONTEND_URL")}/api/reset-password?token={token}"
        
        send_mail(
            'Password Reset Link',
            f'Use the following link to reset your password: {reset_url}',
            os.getenv("EMAIL_HOST_USER")
            [email],
            fail_silently=False
        )
        return Response({'message': 'Password reset link sent successfully.','reset_url':reset_url}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']

            db_handle, _ = get_db_handle()  # Get the MongoDB database handle
            user_collection = db_handle.user_collection
            reset_token_collection = db_handle.reset_token_collection

            # Check if the token is valid and not expired
            token_record = reset_token_collection.find_one({"token": token})
            if not token_record or token_record['expiry'] < datetime.now():
                return Response({'message': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

            # Find the user associated with the token
            user = user_collection.find_one({"_id": token_record['user_id']})
            if not user:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

            # Hash the new password
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

            # Update the user's password
            user_collection.update_one({"_id": user['_id']}, {"$set": {"password": hashed_password}})

            # Remove the token after successful password reset
            reset_token_collection.delete_one({"token": token})

            return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#decode token 
def decode_token(request):

    token = request.headers.get('Authorization', None)
    
    if token is None:
        print("Token not provided")
        return False
        # return Response({'error': 'Token not provided.'}, status=status.HTTP_400_BAD_REQUEST)
    token = token.split(' ')[1] if token.startswith('token ') else token
    try:
        # Decode the JWT token
        decoded_token = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=["HS256"])  # Use your JWT secret key
        seller_id = decoded_token.get('user_id')
        
        if not seller_id:
            return  False
        return seller_id 
    except Exception as e:
        return False
    except jwt.DecodeError:
        return False


class AddCategoryView(APIView):
    def post(self, request):
        getadminID = decode_token(request)
        if not getadminID:
            return Response({'error': 'Please Login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
        try:
            adminID = ObjectId(getadminID)
        except Exception as e:
            return Response({'error': 'Invalid token ID format.'}, status=status.HTTP_400_BAD_REQUEST)
        db_handle, _ = get_db_handle()
        user_data = Database.FindOne(db_handle, Database.USER_COLLECTION, {"_id": adminID})
        if not user_data or user_data['role'] != 'admin':
            return Response({'error': 'You are not authorized to add categories. Admin access required.'}, status=status.HTTP_403_FORBIDDEN)
        
        data = request.data
        title = data.get('title')
        short_description = data.get('short_description')
        product_type = data.get('product_type')

        images = request.FILES.getlist('image')
        if not images:
            return Response({'error': 'At least one image is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if not title or not short_description or not product_type:
            return Response({'error': 'All fields are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            existing_category = Database.FindOne(db_handle, Database.CATEGORY_COLLECTION, {"product_type": product_type})
            if existing_category:
                return Response({'error': f'Product type "{product_type}" already exists. Please choose a different product type.'}, status=status.HTTP_400_BAD_REQUEST)
            # Set up the base URL (protocol and host) for the image URL
            protocol = "https" if request.is_secure() else "http"
            host = request.get_host()

            image_dir = os.path.join(settings.MEDIA_ROOT, 'category_images')
            if not os.path.exists(image_dir):
                os.makedirs(image_dir)
            image_urls = []
            for image in images:
                image_name = f"{title.replace(' ', '_')}_{datetime.utcnow().timestamp()}_{Path(image.name).suffix}" 
                image_path = os.path.join(image_dir, image_name)
                with open(image_path, 'wb') as f:
                    for chunk in image.chunks():
                        f.write(chunk)

                # Generate the image URL
                image_url = f"{protocol}://{host}/media/category_images/{image_name}"
                image_urls.append(image_url)

            # Prepare category data
            db_handle, _ = get_db_handle()

            category = {
                "title": title,
                "image": image_urls,  # Store the list of image URLs
                "short_description": short_description,
                "status": 'active',
                "admin_id": getadminID,
                "product_type": product_type,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }

            # Insert the category into the database
            inserted_id = Database.InsertData(db_handle, Database.CATEGORY_COLLECTION, category)
            category['_id'] = str(inserted_id)
            category=convert_objectid_to_str(category)
            return Response({
                "status": status.HTTP_201_CREATED,
                "message": "Category added successfully.",
                "data": category
            }, status=status.HTTP_201_CREATED)
        # Catch JWT token expiry error
        except Exception as e:
            return Response({'error': 'Token has expired. Please login again.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Catch JWT decoding error (Invalid token)
        except jwt.DecodeError:
            return Response({'error': 'Invalid token. Please provide a valid token.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Catch any other exceptions related to the database insert
        except Exception as e:
            return Response({'error': f'Error inserting data into category_collection: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


from bson import ObjectId
def convert_objectid_to_str(obj):
    if isinstance(obj, dict):
        return {key: convert_objectid_to_str(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_objectid_to_str(item) for item in obj]
    elif isinstance(obj, ObjectId):
        return str(obj)  # Convert ObjectId to string
    else:
        return obj

#get categories by product type in admin section
class GetCategoriesByProductType(APIView):

    def post(self, request):

        # Decode token to get the seller ID
        getsellerID = decode_token(request)
        
        # If the seller ID is not found, return an error
        if not getsellerID:
            return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            # Fetch the seller's categories
            db_handle, _ = get_db_handle()
            categories = Database.FindAll(db_handle, Database.CATEGORY_COLLECTION, {"admin_id": getsellerID})
            
            # If no categories are found for the seller
            if not categories:
                return Response({'error': 'No categories found for this seller.'}, status=status.HTTP_404_NOT_FOUND)
            
            # Initialize response data structure
            product_data = {
                "bracelets": [],
                "earrings": [],
                "ring": [],
                "necklaces": [],
            }
            
            # Process each category
            for category in categories:
                if isinstance(category, dict):
                    category = convert_objectid_to_str(category) 
                    
                    category_product_type = category.get("product_type", "").strip().lower()
                    print(category_product_type,'category_product_type')
                    if category_product_type in product_data:
                        print(f"Adding category {category['title']} to product type {category_product_type}") 
                        product_data[category_product_type].append({
                            '_id': category.get('_id', ''),
                            'title': category.get('title', ''),
                            'short_description': category.get('short_description', ''),
                            'image': category.get('image', ''),
                            'product_type': category.get('product_type', ''),
                            'created_at': category.get('created_at', ''),
                            'updated_at': category.get('updated_at', ''),
                            'status': category.get('status', ''),
                        })
            
            response_data = {
                "bracelets": product_data.get("bracelets", []),
                "earrings": product_data.get("earrings", []),
                "rings": product_data.get("ring", []),
                "necklaces": product_data.get("necklaces", [])
            }
           
            # Return the formatted response
            return Response({
                'status': status.HTTP_200_OK,
                'message': 'Product categories fetched successfully',
                'data': response_data,
            }, status=status.HTTP_200_OK)

        except Exception as e:
            # Handle unexpected errors
            return Response({'error': f'Error fetching categories: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#Get a category in seller section
class GetCategorySeller(APIView):
    def post(self,request):
        
        seller_id = decode_token(request)
        if not seller_id:
            return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
        category_list = []
        db_handle, _ = get_db_handle()
        try:
            categories = Database.FindAll(db_handle, Database.CATEGORY_COLLECTION, {})
            for category in categories:
                category_data = {
                    "title": category.get("title", ""),
                    "category_name": category.get("product_type", ""),
                    "category_id": str(category.get("_id", "")), 
                }
                category_list.append(category_data)
            return Response({"status": status.HTTP_200_OK, "message": "Categories fetched successfully", "data": category_list}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'Error fetching categories: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
#Add Product
class AddProductView(APIView):
    def post(self, request):
        try:
            # Decode token to get the seller ID
            getsellerID = decode_token(request)
            print(getsellerID)
            # If the seller ID is not found, return an error
            if not getsellerID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
            db_handle, _ = get_db_handle()
            user_data = Database.FindOne(db_handle, Database.USER_COLLECTION, {"_id": ObjectId(getsellerID)})
            
            if not user_data:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
            admin_id = None
            user_role = user_data['role']
            if user_role == 'admin':
                product_status = 'admin'
                admin_id = getsellerID
            elif user_role == 'seller':
                product_status = "pending"
                admin_id = None
            else:
                return Response({'error': 'User role is not valid.'}, status=status.HTTP_403_FORBIDDEN)
            data = request.data
            name = data.get('name')
            featured_image = data.get('featured_image')
            short_description = data.get('short_description')
            price = data.get('price')
            discount_percentage = data.get('discount_percentage')
            discount_price = data.get('discount_price')
            tag_string = data.get('tag', '')
            sizes = data.get('sizes')
            colors = data.get('colors')
            gallery_images = request.FILES.getlist('gallery_images')
            category_id = data.get('category_id')
            category_ids = ObjectId(category_id)
            sku = 'null'
            if not gallery_images:
                return Response({'error': 'At least one image is required.'}, status=status.HTTP_400_BAD_REQUEST)
            
            if not name or not featured_image or not short_description or not price or not discount_percentage or not discount_price or not tag_string or not sizes or not colors:
                return Response({'error': 'Missing required fields.'}, status=status.HTTP_400_BAD_REQUEST)
            
            tags = tag_string.split(',') 
            size = sizes.split(',') 
            color = colors.split(',') 
            db_handle, _ = get_db_handle()
            categories = Database.FindAll(db_handle, Database.CATEGORY_COLLECTION, {"_id": category_ids})
            # If no categories are found for the seller
            if not categories:
                return Response({'error': 'No categories found for this seller.'}, status=status.HTTP_404_NOT_FOUND)
            
            # category_ids = [category['_id'] for category in categories]
            protocol = "https" if request.is_secure() else "http"
            host = request.get_host()
            featured_image_dir  = os.path.join(settings.MEDIA_ROOT, 'featured_image')
            gallery_image_dir  = os.path.join(settings.MEDIA_ROOT, 'gallery_images')
            os.makedirs(featured_image_dir, exist_ok=True)
            os.makedirs(gallery_image_dir, exist_ok=True)
            featured_image_name = f"{name.replace(' ', '_')}_featured_{datetime.utcnow().timestamp()}{Path(featured_image.name).suffix}"
            featured_image_path = os.path.join(featured_image_dir, featured_image_name)
            with open(featured_image_path, 'wb') as f:
                for chunk in featured_image.chunks():
                    f.write(chunk)

            featured_image_url = f"{protocol}://{host}/media/featured_image/{featured_image_name}"

            gallery_image_urls = []
            for image in gallery_images:
                image_name = f"{name.replace(' ', '_')}_gallery_{datetime.utcnow().timestamp()}_{Path(image.name).suffix}"
                image_path = os.path.join(gallery_image_dir, image_name)
                with open(image_path, 'wb') as f:
                    for chunk in image.chunks():
                        f.write(chunk)

                # Generate the image URL
                gallery_image_url = f"{protocol}://{host}/media/gallery_images/{image_name}"
                gallery_image_urls.append(gallery_image_url)
            sku = f"SKU-{datetime.utcnow().timestamp()}"
            product = {
                "name": name,
                "featured_image": featured_image_url,
                "short_description": short_description,
                "price":price,
                "discount_percentage":discount_percentage,
                "discount_price":discount_price,
                "tag":tags,
                "sizes":size,
                "colors":color,
                "gallery_images": gallery_image_urls,
                "sku": sku,
                "status": product_status,
                "sellert_id": getsellerID,
                "admin_id":admin_id,
                "category_id": category_id,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            inserted_id = Database.InsertData(db_handle, Database.PRODUCT_COLLECTION, product)
            product['_id'] = str(inserted_id)
            if product_status == "pending":
                seller_email = user_data['email']
                seller_name = user_data.get('first_name', 'Seller')

                subject = "Your product is waiting for admin approval!"
                message = f"""
                Hello {seller_name},

                Your product "{name}" has been successfully added, and it is now awaiting approval from the admin.

                You will receive a notification once your product is approved or rejected.

                Best regards,
                The Team
                """
                from_email = settings.EMAIL_HOST_USER  # Assuming EMAIL_HOST_USER is configured in settings.py
                recipient_list = [seller_email]

                send_mail(
                    subject,
                    message,
                    from_email,
                    recipient_list,
                    fail_silently=False
                )
            return Response({"status": status.HTTP_201_CREATED,'message': 'Product added successfully'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            # Handle unexpected errors
            return Response({'error': f'Error adding product: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
#seller list
class GetUserListAPIView(APIView):
    def post(self, request):
        try:
            # Decode the token to retrieve the seller ID from the request
            getsellerID = decode_token(request)
            # If the seller ID is not found, return an error
            if not getsellerID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
            # Retrieve the database connection handle
            db_handle, _ = get_db_handle()
            # Find the user data based on the decoded seller ID
            user_data = Database.FindOne(db_handle, Database.USER_COLLECTION, {"_id": ObjectId(getsellerID)})
            # If user data is not found, return a "User not found" error
            if not user_data:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
            # Initialize empty lists for sellers and buyers
            sellers, buyers = [], []
            # Get the role of the user (admin, seller, or buyer)
            user_role = user_data['role']
            if user_role == 'admin':
                users = list(Database.FindAll(db_handle, Database.USER_COLLECTION, {"role": {"$in": ["seller", "buyer"]}}))
                sellers = [user for user in users if user.get('role') == 'seller']
                buyers = [user for user in users if user.get('role') == 'buyer']
            elif user_role == 'seller':
                sellers = [user_data]
                buyers = []
            elif user_role == 'buyer':
                buyers = [user_data]
                sellers = []
            else:
                # If the user's role is invalid, return an access denied error
                return Response({'error': 'Invalid role. Access denied.'}, status=status.HTTP_403_FORBIDDEN)
            processed_sellers = self.process_users(sellers)
            processed_buyers = self.process_users(buyers)
            # Return a success response with the processed lists of sellers and buyers
            return Response({
                "status": status.HTTP_200_OK,
                "message": "Users fetched successfully.",
                "data": processed_sellers,
                "buyers": processed_buyers
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {'error': f'Error fetching products: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @staticmethod
    def process_users(users):
        """
        Process user list by converting ObjectId to string.
        """
        processed_users = []
        for user in users:
            if isinstance(user, dict):
                user['_id'] = str(user.get('_id'))
                processed_users.append(user)
        return processed_users


#Get product list admin and seller
class GetAllProductListAPIView(APIView):
    def post(self,request):
        try:
            getsellerID = decode_token(request)
            if not getsellerID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
            db_handle, _ = get_db_handle()
            userdetails = Database.FindAll(db_handle, Database.USER_COLLECTION,{"_id":ObjectId(getsellerID)})
            if userdetails[0]['role'].lower()=="seller":
                getProduct = Database.FindAll(db_handle, Database.PRODUCT_COLLECTION, {"sellert_id": getsellerID})
            elif userdetails[0]['role'].lower()=="admin":
                getProduct = Database.FindAll(db_handle, Database.PRODUCT_COLLECTION,{})
                
            if getProduct:
                for product in getProduct:
                    product['_id'] = str(product['_id'])
                return Response({"status": "success", "products": getProduct}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'No products found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Error retrieving product list: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import InMemoryUploadedFile, TemporaryUploadedFile
# # Edit category
# class EditCategoryAPIView(APIView):
#     def put(self, request):
#         try:
#             getsellerID = decode_token(request)
#             if not getsellerID:
#                 return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)

#             category_id = request.data.get("category_id")
#             if not category_id:
#                 return Response({'error': 'Category ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

#             db_handle, _ = get_db_handle()

#             category = Database.FindOne(db_handle, Database.CATEGORY_COLLECTION, {"_id": ObjectId(category_id)})
#             print(category,'category')
#             if not category:
#                 return Response({'error': 'Category not found.'}, status=status.HTTP_404_NOT_FOUND)
#             title = request.data.get('title', category['title'])
#             short_description = request.data.get('short_description', category['short_description'])
#             product_type = request.data.get('product_type', category['product_type'])
#             uploaded_images = request.data.get('image')

#             # Get existing images from the database
#             existing_images = category.get('image', [])

#             # Prepare list to store image URLs
#             image_urls = existing_images.copy()
#             image_urls = []

#             if type(uploaded_images)!=str:
#                 protocol = "https" if request.is_secure() else "http"
#                 host = request.get_host()
#                 image_dir = os.path.join(settings.MEDIA_ROOT, 'category_images')

#                 if not os.path.exists(image_dir):
#                     os.makedirs(image_dir)
#                 for image in uploaded_images:
#                     # if isinstance(image, InMemoryUploadedFile):
#                     # Ensure it's an instance of InMemoryUploadedFile
#                     print(f'Handling file upload: {image.name}')
#                     image_name = f"{title.replace(' ', '_')}_{datetime.utcnow().timestamp()}_{Path(image.name).suffix}"
#                     image_path = os.path.join(image_dir, image_name)

#                     # Save the image to the file system
#                     with open(image_path, 'wb') as f:
#                         for chunk in image.chunks():
#                             f.write(chunk)

#                     # Generate the image URL
#                     image_url = f"{protocol}://{host}/media/category_images/{image_name}"
#                     image_urls.append(image_url)
#             # else:
#             #     print('inside else')
#             #     # If no new images are uploaded, use the existing images
#             #     image_urls = existing_images
#             #     print(image_urls,'image urls')
#             if not title or not short_description or not product_type:
#                 return Response({'error': 'Title, short description, and product type are required.'}, status=status.HTTP_400_BAD_REQUEST)

#             # Step 6: Prepare the data to update the category
#             update_data = {
#                 "title": title,
#                 "short_description": short_description,
#                 "product_type": product_type,
#                 "image": image_urls,  
#                 "updated_at": datetime.utcnow().isoformat()  # Set the updated timestamp
#             }
#             if type(uploaded_images)!=str:
#                 update_data["image"] = image_urls 
#             update_result = Database.Update(db_handle, Database.CATEGORY_COLLECTION, {"_id": ObjectId(category_id)}, update_data)
#             if update_result.matched_count == 0:
#                 return Response({'error': 'Failed to update category.'}, status=status.HTTP_400_BAD_REQUEST)
#             return Response({
#                 'status': 'Category updated successfully!',
#                 'category_id': category_id,
#                 'updated_data': update_data,
#                 # 'image_urls': image_urls
#             }, status=status.HTTP_200_OK)

#         except Exception as e:
#             return Response({'error': f'Error updating category: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class EditCategoryAPIView(APIView):
    def put(self, request):
        try:
            getsellerID = decode_token(request)
            if not getsellerID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)

            category_id = request.data.get("category_id")
            if not category_id:
                return Response({'error': 'Category ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

            db_handle, _ = get_db_handle()

            category = Database.FindOne(db_handle, Database.CATEGORY_COLLECTION, {"_id": ObjectId(category_id)})
            if not category:
                return Response({'error': 'Category not found.'}, status=status.HTTP_404_NOT_FOUND)

            # Retrieve values from request data, falling back to current category values
            title = request.data.get('title', category['title'])
            short_description = request.data.get('short_description', category['short_description'])
            product_type = request.data.get('product_type', category['product_type'])
            uploaded_images = request.FILES.getlist('image') or  request.data.get('image')
            print(uploaded_images,'uploaded_images')
            # Get existing images from the database
            existing_images = category.get('image', [])

            # Prepare list to store image URLs
            # image_urls = existing_images.copy()  # Start with existing images
            # print(image_urls,'image_urls')
            # If new images are uploaded, process them
            if type(uploaded_images)!=str:
                protocol = "https" if request.is_secure() else "http"
                host = request.get_host()
                image_dir = os.path.join(settings.MEDIA_ROOT, 'category_images')

                # Ensure image directory exists
                if not os.path.exists(image_dir):
                    os.makedirs(image_dir)
                image_urls =[]
                # Handle each uploaded image
                for image in uploaded_images:
                    print('inasei loop')
                    print(image,'image')
                    image_name = f"{title.replace(' ', '_')}_{datetime.utcnow().timestamp()}{Path(image.name).suffix}"
                    image_path = os.path.join(image_dir, image_name)

                    # Save the image to disk
                    with open(image_path, 'wb') as f:
                        for chunk in image.chunks():
                            f.write(chunk)

                    # Generate the URL for the uploaded image
                    image_url = f"{protocol}://{host}/media/category_images/{image_name}"
                    image_urls.append(image_url)  # Add the new image URL to the list
            else:
                print('insie eslse')
                image_urls = existing_images
            # Ensure required fields are present
            if not title or not short_description or not product_type:
                return Response({'error': 'Title, short description, and product type are required.'}, status=status.HTTP_400_BAD_REQUEST)

            # Prepare the data to update the category
            update_data = {
                "title": title,
                "short_description": short_description,
                "product_type": product_type,
                "image": image_urls if image_urls else uploaded_images,  # Only update image if it was provided
                "updated_at": datetime.utcnow().isoformat()  # Set the updated timestamp
            }

            # Perform the update
            update_result = Database.Update(db_handle, Database.CATEGORY_COLLECTION, {"_id": ObjectId(category_id)}, update_data)

            if update_result.matched_count == 0:
                return Response({'error': 'Failed to update category.'}, status=status.HTTP_400_BAD_REQUEST)

            # Return success response
            return Response({
                'status': 'Category updated successfully!',
                'category_id': category_id,
                'updated_data': update_data,
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': f'Error updating category: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class EditProductAPIView(APIView):
    def put(self, request):
        try:
            getsellerID = decode_token(request)
            if not getsellerID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)

            product_id = request.data.get("product_id")
            if not product_id:
                return Response({'error': 'Product ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

            db_handle, _ = get_db_handle()
            
            product = Database.FindOne(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product_id)})
            user_role = product['status']
            print(user_role,'?????')
            if user_role not in ['admin', 'seller']:
                return Response({'error': 'Role is not valid.'}, status=status.HTTP_403_FORBIDDEN)
            # if user_role == 'seller' and product.get('seller_id') != getsellerID:
            #     return Response({'error': 'You can only update your own products.'}, status=status.HTTP_403_FORBIDDEN)
            print(request.data,type(request.data))
            name = request.data.get('name', product['name'])
            featured_image = request.data.get('featured_image', product['featured_image'])
            short_description = request.data.get('short_description', product['short_description'])
            discount_price = request.data.get('discount_price', product['discount_price'])
            discount_percentage = request.data.get('discount_percentage', product['discount_percentage'])
            price = request.data.get('price', product['price'])
            tag_string = request.data.get('tag', product['tag'])
            sizes = request.data.get('sizes', product['sizes'])
            colors = request.data.get('colors', product['colors'])
            gallery_images = request.FILES.getlist('gallery_images')
            if not product:
                return Response({'error': 'Product not found.'}, status=status.HTTP_404_NOT_FOUND)
            if not gallery_images and not product.get('gallery_images'):
                return Response({'error': 'At least one image is required.'}, status=status.HTTP_400_BAD_REQUEST)
            protocol = "https" if request.is_secure() else "http"
            host = request.get_host()
            print(featured_image,'??????')
            print(type(featured_image),'??????')
            if type(featured_image)!=str :
                featured_image_name = f"{uuid.uuid4().hex}_{featured_image.name}"
                featured_image_path = os.path.join(settings.MEDIA_ROOT, 'featured_image', featured_image_name)
                with open(featured_image_path, 'wb') as f:
                    for chunk in featured_image.chunks():
                        f.write(chunk)
                featured_image_url = f"{protocol}://{host}/media/gallery_images/{featured_image_name}"
            else:
                featured_image_url = product['featured_image']
            gallery_image_paths =[]
            if type(gallery_images) !=str:
                for gallery_image in gallery_images:
                    gallery_image_name = f"{uuid.uuid4().hex}_{gallery_image.name}"
                    gallery_image_path = os.path.join(settings.MEDIA_ROOT, 'gallery_images', gallery_image_name)
                    with open(gallery_image_path, 'wb') as f:
                        for chunk in gallery_image.chunks():
                            f.write(chunk)
                    image_url = f"{protocol}://{host}/media/gallery_images/{gallery_image_name}"
                    gallery_image_paths.append(image_url)
            else:
                gallery_image_paths = product.get('gallery_images', [])
            tags = tag_string.split(',') 
            size = sizes.split(',') 
            color = colors.split(',')
            updated_product_data = {
                'name': name,
                'featured_image': featured_image_url,
                'short_description': short_description,
                'discount_price': discount_price,
                'discount_percentage': discount_percentage,
                'price': price,
                'tag': tags,
                'sizes': size,
                'colors': color,
                'gallery_images': gallery_image_paths,
                'updated_at': datetime.utcnow().isoformat()  # Set the updated timestamp
            }
            update_result = Database.Update(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product_id)}, updated_product_data)
            if update_result.matched_count == 0:
                return Response({'error': 'Failed to update product.'}, status=status.HTTP_400_BAD_REQUEST)
            return Response({
                'status': 'Category updated successfully!',
                'category_id': product_id,
                'updated_data': updated_product_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            print(e)
            return Response({'error': 'An error occurred while updating the product.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class DeleteProductAPIView(APIView):
    def delete(self,request):
        try:
            getsellerID = decode_token(request)
            if not getsellerID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)
            product_id = request.data.get('product_id')
            db_handle, _ = get_db_handle()
            product = Database.FindOne(db_handle,Database.PRODUCT_COLLECTION,{"_id":ObjectId(product_id)})
            if not product:
                return Response({"status":status.HTTP_200_OK,"message":"Product not found."})
            user_role = product['status']
            if user_role:
                delete_result = Database.Delete(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product_id)})
                if delete_result and delete_result.deleted_count > 0:
                    return Response({"status": status.HTTP_200_OK, "message": "Product deleted successfully."})
                else:
                    return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Failed to delete product."})
            # elif user_role == 'seller' and product.get('seller_id') == getsellerID:
            #     # Only the seller who created the product can delete it
            #     delete_result = Database.Delete(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product_id)})
            #     if delete_result and delete_result.deleted_count > 0:
            #         return Response({"status": status.HTTP_200_OK, "message": "Product deleted successfully."})
            #     else:
            #         return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Failed to delete product."})
            else:
                return Response({"status": status.HTTP_403_FORBIDDEN, "message": "You are not authorized to delete this product."})
        except Exception as e:
            print(e)
            return Response({"status":status.HTTP_400_BAD_REQUEST,"message":"An error occurred while deleting the product."})


class AdminApproveProduct(APIView):
    def post(self, request):
        try:
            # Decode token to get the admin's ID
            gettokenID = decode_token(request)
            if not gettokenID:
                return Response({'error': 'Please login again or check the token.'}, status=status.HTTP_403_FORBIDDEN)

            # Get product and status details from request
            product_id = request.data.get('product_id')
            status_value = request.data.get('status')
            if status_value.lower() not in ['approved', 'declined']:
                return Response({'error': 'Invalid status. It should be either "approve" or "decline".'}, status=status.HTTP_400_BAD_REQUEST)
            status_value = status_value.title()
            db_handle, _ = get_db_handle()
            product = Database.FindOne(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product_id)})
            user_id = Database.FindOne(db_handle, Database.USER_COLLECTION, {"_id": ObjectId(product['sellert_id'])})
            print(user_id['email'],'user_id')
            if not product:
                return Response({'error': 'Product not found for the given seller ID.'}, status=status.HTTP_404_NOT_FOUND)
            product_data = {
                'status': status_value,
                
            }
            if status_value:
                update_result = Database.Update(db_handle, Database.PRODUCT_COLLECTION, {"_id": ObjectId(product['_id'])},product_data)
                if update_result.matched_count == 0:
                    return Response({'error': 'Product update failed.'}, status=status.HTTP_404_NOT_FOUND)

                # Send approval email to the seller
                seller = Database.FindOne(db_handle, Database.PRODUCT_COLLECTION, {"sellert_id": product['sellert_id']})
                if seller:
                    subject = f"Your product has been {status_value}!"
                    message = f"""
                    Hello {seller.get('first_name', 'User')},

                    Your product "{product['name']}" has been successfully {status_value} by the admin.

                    Best regards,
                    The Team
                    """
                    from_email = settings.EMAIL_HOST_USER
                    recipient_list = [user_id['email']]

                    send_mail(
                        subject,
                        message,
                        from_email,
                        recipient_list,
                        fail_silently=False
                    )

                return Response({
                    'status': status.HTTP_200_OK,
                    'message': f'Product {status_value} and email sent to seller.'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'status': status.HTTP_200_OK,
                    'message': 'Product Unavailable and try after some time.'
                }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

