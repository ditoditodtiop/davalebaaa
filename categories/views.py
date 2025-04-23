from rest_framework.generics import GenericAPIView
from rest_framework.mixins import ListModelMixin,RetrieveModelMixin,CreateModelMixin
from rest_framework.permissions import IsAuthenticated
from rest_framework.filters import SearchFilter
from rest_framework.viewsets import GenericViewSet
from django_filters.rest_framework import DjangoFilterBackend
from categories.serializers import CategorySerializer,CategoryDetailSerializer,CategoryImageSerializer
from categories.models import Category,CategoryImage

class CategoryListViewSet(ListModelMixin,RetrieveModelMixin,GenericViewSet):
    queryset=Category.objects.all()
    serializer_class=CategorySerializer
    filter_backends=[SearchFilter]
    search_fields=['name']


class CategoryImageViewSet(ListModelMixin,CreateModelMixin,GenericViewSet):
    queryset=CategoryImage.objects.all()
    serializer_class=CategoryImageSerializer

    def get_queryset(self):
        category_id=self.kwargs['category_pk']

        return self.queryset.filter(category=category_id)