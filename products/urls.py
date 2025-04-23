from django.urls import path,include
from rest_framework.routers import SimpleRouter,DefaultRouter
from rest_framework_nested import routers
from products.views import ProductViewSet,ReviewViewSet,CartViewSet,ProductTagListViewSet,FavoriteProductViewSet,ProductImageViewSet,CartItemViewSet

router=routers.DefaultRouter()
router.register('products',ProductViewSet)
router.register('favorite_products',FavoriteProductViewSet,basename='favorite-products')
router.register('cart',CartViewSet)
router.register('tags',ProductTagListViewSet)
router.register('cart_items',CartItemViewSet,basename='cart-items')

product_router=routers.NestedDefaultRouter(
    router,'products',lookup='product'
)
product_router.register('images',ProductImageViewSet,basename='product-images')
product_router.register('reviews',ReviewViewSet,basename='product-reviews')

urlpatterns = [
    path('',include(router.urls)),
    path('',include(product_router.urls)),
]