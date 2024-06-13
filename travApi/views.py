from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import *
from .serializers import  *
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework.decorators import api_view


User = get_user_model()


class UserCreateView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProfileUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            profile = Profile.objects.get(user=request.user)
            serializer = ProfileSerializer(instance=profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Profile.DoesNotExist:
            return Response({"detail": "Profile not found"}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, *args, **kwargs):
        try:
            profile = Profile.objects.get(user=request.user)
            serializer = ProfileSerializer(instance=profile, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Profile.DoesNotExist:
            return Response({"detail": "Profile not found"}, status=status.HTTP_404_NOT_FOUND)
    
class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

    def post(self, request, *args, **kwargs):
        serializer = PasswordChangeSerializer(data=request.data, context={'user': request.user})
        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "Password changed successfully."}, status=status.HTTP_200_OK)
        return Response({"detail": "Invalid input data for password change"}, status=status.HTTP_400_BAD_REQUEST)
    
class LoginView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            password = serializer.validated_data.get('password')

            try:
                user = User.objects.get(email=email)
                if user.check_password(password):
                    token, _ = Token.objects.get_or_create(user=user)
                    return Response({"token": token.key}, status=status.HTTP_200_OK)
                else:
                    return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
            except User.DoesNotExist:
                return Response({"detail": "User not found", "code": "user_not_found"}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            token = Token.objects.get(user=request.user)
            # Delete the token
            token.delete()
            return Response({"detail": "Logout successful"}, status=status.HTTP_200_OK)
        except Token.DoesNotExist:
            return Response({"detail": "No token found for the user"}, status=status.HTTP_404_NOT_FOUND)


class PasswordResetView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if email:
            user = User.objects.filter(email=email)
            if user.exists():
                user = user.first()
                token_generator = PasswordResetTokenGenerator()
                token = token_generator.make_token(user)
                uidb64 = urlsafe_base64_encode(str(user.pk).encode())
                protocol = 'https' if request.is_secure() else 'http'
                domain = request.get_host()
                url = f'{protocol}://{domain}/api/auth/passwordreset/confirm/{uidb64}/{token}/'
                return Response({'message': 'Password reset email sent'}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'message': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=int(uid))
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and PasswordResetTokenGenerator().check_token(user, token):
            password1 = request.data.get('password1')
            password2 = request.data.get('password2')
            if password1 and password2:
                if password1!= password2:
                    return Response({'message': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
                user.set_password(password1)
                user.save()
                return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'Passwords are required'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'message': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
#########################vehicle#######################################################
@api_view(['GET'])
def vehicle_list(request):
    if request.method == 'GET':
        vehicles = Vehicle.objects.all()
        serializer = VehicleSerializer(vehicles, many=True)
        return Response(serializer.data)

@api_view(['POST'])
def vehicle_create(request):
    if request.method == 'POST':
        serializer = VehicleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def vehicle_get(request, vehicle_id):
    vehicle = Vehicle.objects.get(vehicle_id=vehicle_id)
    if request.method == 'GET':
        serializer = VehicleSerializer(vehicle)
        return Response(serializer.data)

@api_view(['PUT', 'PATCH'])
def vehicle_update(request, vehicle_id):
    vehicle = Vehicle.objects.get(vehicle_id=vehicle_id)
    if request.method == 'PUT' or request.method == 'PATCH':
        serializer = VehicleSerializer(vehicle, data=request.data, partial=(request.method == 'PATCH'))
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
def vehicle_delete(request, vehicle_id):
    vehicle = Vehicle.objects.get(vehicle_id=vehicle_id)
    if request.method == 'DELETE':
        vehicle.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

#################################trip###########################################################
@api_view(['GET'])
def trip_list(request):
    if request.method == 'GET':
        trips = Trip.objects.all()
        serializer = TripSerializer(trips, many=True)
        return Response(serializer.data)
@api_view(['POST'])
def trip_create(request):
    if request.method == 'POST':
        serializer = TripSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def trip_get(request, trip_id):
    trip = Trip.objects.get(trip_id=trip_id)
    if request.method == 'GET':
        serializer = TripSerializer(trip)
        return Response(serializer.data)
@api_view(['PUT', 'PATCH'])
def trip_update(request, trip_id):
    trip = Trip.objects.get(trip_id=trip_id)
    if request.method == 'PUT' or request.method == 'PATCH':
        serializer = TripSerializer(trip, data=request.data, partial=(request.method == 'PATCH'))
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
def trip_delete(request, trip_id):
    trip = Trip.objects.get(trip_id=trip_id)
    if request.method == 'DELETE':
        trip.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

########################################booking###########################################
@api_view(['GET'])
def booking_list(request):
    if request.method == 'GET':
        bookings = Booking.objects.all()
        serializer = BookingSerializer(bookings, many=True)
        return Response(serializer.data)
@api_view(['POST'])
def booking_create(request):
    if request.method == 'POST':
        serializer = BookingSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def booking_get(request, booking_id):
    booking = Booking.objects.get(booking_id=booking_id)
    if request.method == 'GET':
        serializer = BookingSerializer(booking)
        return Response(serializer.data)
@api_view(['PUT', 'PATCH'])
def booking_update(request, booking_id):
    booking = Booking.objects.get(booking_id=booking_id)
    if request.method == 'PUT' or request.method == 'PATCH':
        serializer = BookingSerializer(booking, data=request.data, partial=(request.method == 'PATCH'))
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
@api_view(['DELETE'])
def booking_delete(request, booking_id):
    booking = Booking.objects.get(booking_id=booking_id)
    if request.method == 'DELETE':
        booking.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)