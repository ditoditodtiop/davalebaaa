from django.db import models
from django.core.validators import MaxValueValidator
from config.model_utils.models import TimeStampedModel
from products.choices import Currency
from django.conf import settings
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from config.utils.image_validators import validate_image_resolution,validate_image_size,validate_image_count

class Product(TimeStampedModel, models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE,related_name='products',null=False)
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.FloatField()
    currency = models.CharField(max_length=255, choices=Currency.choices, default=Currency.GEL)
    tags = models.ManyToManyField("products.ProductTag", related_name='products', blank=True)
    quantity=models.PositiveIntegerField()
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Product: {self.name} - {self.price} {self.currency}"

    def average_rating(self):
        pass


class Review(TimeStampedModel, models.Model):
    product = models.ForeignKey('products.Product', related_name='reviews', on_delete=models.CASCADE)
    user = models.ForeignKey('users.User', on_delete=models.SET_NULL, null=True, blank=True)
    content = models.TextField()
    rating = models.PositiveIntegerField(validators=[MaxValueValidator(5)])
    
    class Meta:
        unique_together=['product','user']

    def __str__(self):
        return f"Review by {self.user} for {self.product.name} - Rating: {self.rating}"


class FavoriteProduct(TimeStampedModel, models.Model):
    product = models.ForeignKey('products.Product', on_delete=models.CASCADE)
    user = models.ForeignKey('users.User', on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"{self.user} favorite: {self.product.name}"


class ProductTag(TimeStampedModel, models.Model):
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return f"Tag: {self.name}"


class Cart(TimeStampedModel, models.Model):
    products = models.ManyToManyField('products.Product', related_name='carts')
    user = models.OneToOneField('users.User', on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"Cart for {self.user}"


class ProductImage(TimeStampedModel, models.Model):
    image = models.ImageField(upload_to='products/',validators=[validate_image_size,validate_image_resolution])
    product = models.ForeignKey('products.Product', related_name='images', on_delete=models.CASCADE)

    def clean(self):
        if self.product_id:
            validate_image_count(self.product_id)
        super().clean()
    
    def save(self,*args,**kwargs):
        self.full_clean()
        super().save(*args,**kwargs)
    
    def __str__(self):
        return f"Image for {self.product.name}"

class CartItem(TimeStampedModel,models.Model):
    cart=models.ForeignKey(Cart, related_name='items',on_delete=models.CASCADE)
    product=models.ForeignKey(Product, related_name='cart_items',on_delete=models.CASCADE)
    quantity=models.PositiveIntegerField(default=1)
    price_at_time_of_addition=models.FloatField()

    def str(self):
        return f'{self.product.name} - {self.quantity}'

    def total_price(self):
        return self.quantity * self.price_at_time_of_addition