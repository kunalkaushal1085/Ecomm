"""
URL configuration for ecom project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from ecomapp import views

urlpatterns = [
    path('customer-register', views.UserRegistrationView.as_view(), name='customer-register'),
    path('customer-login', views.UserLoginView.as_view(), name='customer-login'),
    path('approved-seller', views.AdminApproveSellerView.as_view(), name='approved-seller'),
    path('forgot-password', views.PasswordResetRequestView.as_view(), name='forgot_password'),
    path('reset-password', views.PasswordResetConfirmView.as_view(), name='reset_password'),
    path('add-category', views.AddCategoryView.as_view(), name='add-categorys'),
    path('get-category', views.GetCategoriesByProductType.as_view(), name='get-categorys'),
    path('get-admin-category', views.GetCategorySeller.as_view(), name='get-admin-categorys'),
    path('add-product', views.AddProductView.as_view(), name='add-products'),
    path('get-user-list', views.GetUserListAPIView.as_view(), name='get-user-lists'),#admin can access all user list like seller and user
    path('get-all-product-list', views.GetAllProductListAPIView.as_view(), name='get-all-product'),#admin & seller can get all product list
    path('edit-category', views.EditCategoryAPIView.as_view(), name='edit-categories'),# Edit category
    path('edit-product', views.EditProductAPIView.as_view(), name='edit-products'),# product can edit by admin and seller 
    path('delete-product', views.DeleteProductAPIView.as_view(), name='delete-products'), 
    path('approved-product', views.AdminApproveProduct.as_view(), name='approved-product'),# admin can approve seller product
    path('add-cart', views.AddToCartAPIView.as_view(), name='add-cart'),
    path('remove-cart', views.RemoveFromCartAPIView.as_view(), name='remove-cart'),
    path('buyer-product-list', views.ApprovedProductsAPIView.as_view(), name='buyer-product-list'),
    path('Checkout-Session', views.CheckoutSessionView.as_view(), name='Checkout-Session'),
    path('payment-success', views.PaymentSuccessAPIView.as_view(), name='payment-success'),
    path('seller-order', views.SellerOrderApiView.as_view(), name='seller-order'),
    path('order-tracking', views.OrderTrackingAPIView.as_view(), name='order-tracking'),
    path('shipping-address', views.AddressFetchAPIView.as_view(), name='billing-shipping-address'),
    path('account-details', views.AccountdetailsAPIview.as_view(), name='account-details'),
]