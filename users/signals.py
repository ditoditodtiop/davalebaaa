from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from users.models import User
from products.models import Cart

@receiver(post_save, sender=User)
def create_user_cart(sender, instance, created, **kwargs):
    if created:
        cart, created = Cart.objects.get_or_create(user=instance)
        print(f"🛒 Cart created for user: {instance.email}")

@receiver(post_delete, sender=User)
def delete_user_cart(sender, instance, **kwargs):
    """
    When a user is deleted, delete their cart as well.
    """
    Cart.objects.filter(user=instance).delete()
    print(f"🗑️ Cart deleted for user: {instance.email}")
