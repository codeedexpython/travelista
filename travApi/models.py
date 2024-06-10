from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone
from django.core.validators import RegexValidator,MaxValueValidator, MinValueValidator
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
User = get_user_model()

class UserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    date_of_birth = models.DateField(null=True, blank=True)
    phone_number = models.CharField(
        max_length=10,
        validators=[RegexValidator(r'^[6-9]\d{9}$')]
    )
    profile_picture = models.ImageField(upload_to='profile_pictures/')
    address = models.CharField(max_length=250)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    country = models.CharField(max_length=50)
    zip_code = models.CharField(max_length=10)

    def __str__(self):
        return self.phone_number
    
class RideAndDrive(models.Model):
    USER_TYPES = [
        ('user', 'User'),
        ('driver', 'Driver'),
        ('both', 'Both'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    user_type = models.CharField(max_length=10, choices=USER_TYPES, default='user')
    vehicle_information = models.TextField(null=True, blank=True)
    driver_license = models.CharField(max_length=30, null=True, blank=True)
    license_expiration_date = models.DateField(null=True, blank=True)
    driver_rating = models.DecimalField(
        max_digits=2, decimal_places=1, null=True, blank=True,
        validators=[MinValueValidator(1.0), MaxValueValidator(5.0)]
    )
    rider_rating = models.DecimalField(
        max_digits=2, decimal_places=1, null=True, blank=True,
        validators=[MinValueValidator(1.0), MaxValueValidator(5.0)]
    )
    availability_status = models.BooleanField(default=True)
    preferred_payment_method = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        return self.user_type
    

class Vehicle(models.Model):
    vehicle_id=models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    vehicle_type = models.CharField(max_length=50)
    make = models.CharField(max_length=50)
    model = models.CharField(max_length=50)
    year = models.CharField(max_length=4)
    license_plate = models.CharField(max_length=20, unique=True)
    color = models.CharField(max_length=30)
    seats_available = models.PositiveIntegerField()
    registration_document = models.URLField()

    class Meta:
        db_table="vehicle_table"

class Trip(models.Model):
    trip_id=models.AutoField(primary_key=True)
    driver = models.ForeignKey(User,on_delete=models.CASCADE)
    vehicle_id= models.ForeignKey(Vehicle, on_delete=models.CASCADE)
    start_location = models.CharField(max_length=255)
    end_location = models.CharField(max_length=255)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    available_seats = models.IntegerField()
    fare = models.IntegerField()
    
    class Meta:
        db_table="trip_table"

class Booking(models.Model):
    booking_id=models.AutoField(primary_key=True)
    trip_id= models.ForeignKey(Trip, on_delete=models.CASCADE)
    passenger= models.ForeignKey(User, on_delete=models.CASCADE)
    seats_booked = models.IntegerField()
    booking_time = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default='pending')

    class Meta:
        db_table = "booking_table"


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()