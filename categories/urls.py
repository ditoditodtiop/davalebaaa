from django.urls import path,include
from rest_framework.routers import SimpleRouter,DefaultRouter
from rest_framework_nested import routers
from categories.views import CategoryListViewSet,CategoryImageViewSet

router=routers.DefaultRouter()
router.register('categories',CategoryListViewSet)

category_router=routers.NestedDefaultRouter(
    router,'categories',lookup='category'
)
category_router.register('images',CategoryImageViewSet)


urlpatterns = [
    path('',include(router.urls)),
    path('',include(category_router.urls))
    # path('categories/',CategoryListView.as_view(), name="categories"),
    # path('categories/<int:pk>/',CategoryDetailView.as_view(), name="category"),
    # path('categories/<int:category_id>/images/',CategoryImageViewSet.as_view(), name="images"),
]