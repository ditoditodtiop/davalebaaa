from django.core.validators import ValidationError
from PIL import Image

def validate_image_size(image):
    size=image.size
    limit=5
    if size>=limit*1024*1024:
        raise ValidationError(f"suratis zoma ar unda aghematebodes {limit} MB")
    
def validate_image_resolution(image):
    min_height,min_width=300,400
    max_height,max_width=4000,4000
    img=Image.open(image)
    img_width,img_heigth=img.size
    
    if img_width>=max_width or img_heigth>=max_height:
        raise ValidationError("maxsimaluri dashvebuli suratis gafartoveba aris 4000x4000 pixel")
    if img_width>=min_width or img_heigth>=min_height:
        raise ValidationError("minimaluri dashvebuli suratis gafartoveba aris 300x300 pixel")


from django.apps import apps

def validate_image_count(product_id):
    ProductImage=apps.get_model("products","ProductImage")
    limit=5 
    count=ProductImage.objects.filter(product_id=product_id).count()
    if count>=limit:
        raise ValidationError('1 productze dashvebulia maximum 5 suratis atvirtva')
    