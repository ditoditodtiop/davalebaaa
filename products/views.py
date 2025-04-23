from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework.mixins import ListModelMixin,CreateModelMixin,RetrieveModelMixin,UpdateModelMixin,DestroyModelMixin
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet
from rest_framework.generics import GenericAPIView,ListAPIView,ListCreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from rest_framework.filters import SearchFilter
from django_filters.rest_framework import DjangoFilterBackend
from products.models import Product,Review,Cart,ProductTag,FavoriteProduct,ProductImage,CartItem
from products.permissions import IsObjectOwnerOrReadOnly
from products.filters import ProductFilter,ReviewFilter
from products.serializers import ProductSerializer,ReviewSerializer,CartSerializer,ProductTagSerializer,ProductImageSerializer,FavoriteProductSerializer,CartItemSerializer
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from rest_framework.parsers import MultiPartParser,FormParser
from django.core.validators import ValidationError


class ProductViewSet(ListModelMixin,CreateModelMixin,DestroyModelMixin,RetrieveModelMixin,UpdateModelMixin,GenericViewSet):
    queryset=Product.objects.all()
    serializer_class=ProductSerializer
    permission_classes=[IsAuthenticated,IsObjectOwnerOrReadOnly]
    filterset_class=ProductFilter
    filter_backends=[DjangoFilterBackend,SearchFilter]
    search_fields=['name','desciption']
    
class ReviewViewSet(ModelViewSet):
    queryset=Review.objects.all()
    serializer_class=ReviewSerializer
    permission_classes=[IsAuthenticated,IsObjectOwnerOrReadOnly]
    filterset_class=ReviewFilter
    filter_backends=[DjangoFilterBackend]
    
    def get_queryset(self):
        return self.queryset.filter(product_id=self.kwargs['product_pk'])
    
    def perform_destroy(self, instance):
        if instance.user != self.request.user:
            raise PermissionDenied('You cant delete this review')
        instance.delete()
        
    def perform_update(self,serializer):
        instance=self.get_object()
        if instance.user!=self.request.user:
            raise PermissionDenied("You cant change this review")
        serializer.save()

class CartViewSet(ListModelMixin,CreateModelMixin,GenericViewSet):
    queryset=Cart.objects.all()
    serializer_class=CartSerializer
    permission_clases=[IsAuthenticated]
    
    def get_queryset(self):
        queryset=self.queryset.filter(user=self.request.user)
        return queryset
    
    
class ProductTagListViewSet(ListModelMixin,GenericViewSet):
    queryset=ProductTag.objects.all()
    serializer_class=ProductTagSerializer
    permission_classes=[IsAuthenticated]
    
class FavoriteProductViewSet(ListModelMixin,RetrieveModelMixin,DestroyModelMixin,CreateModelMixin,GenericViewSet):
    queryset=FavoriteProduct.objects.all()
    serializer_class=FavoriteProductSerializer
    permission_clases=[IsAuthenticated]
    
    def get_queryset(self):
        queryset=self.queryset.filter(user=self.request.user)
        return queryset
    
class ProductImageViewSet(ListModelMixin,RetrieveModelMixin,DestroyModelMixin,CreateModelMixin,GenericViewSet):
    queryset=ProductImage.objects.all()
    serializer_class=ProductImageSerializer
    permission_classes=[IsAuthenticated]
    parser_classes=[MultiPartParser,FormParser]
    
    def get_queryset(self):
        return self.queryset.filter(product__id=self.kwargs['product_pk'])
    
    def create(self,request,*args,**kwargs):
        try:
            super().create(request,*args,**kwargs)
        except ValidationError as e:
            return Response({"error":"{e}"},status=status.HTTP_400_BAD_REQUEST)
        
class CartItemViewSet(ModelViewSet):
    queryset=CartItem.objects.all()
    serializer_class=CartItemSerializer
    permission_classes=[IsAuthenticated]

    def get_queryset(self):
        return self.queryset.filter(cart__user=self.request.user)
    
    def perform_destroy(self, instance):
        if instance.cart.user!=self.request.user:
            raise PermissionDenied("You do not have permission to delete this item.")
        instance.delete()

    def perform_update(self, serializer):
        instance=self.get_object()
        if instance.cart.user!=self.request.user:
            raise PermissionDenied("You do not have permission to update this item.")
        serializer.save()