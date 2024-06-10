from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
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


