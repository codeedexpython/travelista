from django.urls import path
from .views import  *


urlpatterns = [
    path('auth/register/', UserCreateView.as_view(), name='create-user'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('profile/', ProfileUpdateView.as_view(), name='update-profile'),
    path('password/change/', PasswordChangeView.as_view(), name='password_change'),
    path('password/reset/', PasswordResetView.as_view(), name='password_reset'),
    path('auth/passwordreset/confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('vehicle_list',vehicle_list,name='vehicle_list'),
    path('vehicle_create',vehicle_create,name='vehicle_create'),
    path('vehicle/<int:vehicle_id>',vehicle_get,name='vehicle_get'),
    path('update_vehicle/<int:vehicle_id>',vehicle_update,name='vehicle_update'),
    path('delete_vehicle/<int:vehicle_id>',vehicle_delete,name='vehicle_delete'),
    path('trip_list',trip_list,name='trip_list'),
    path('trip_create',trip_create,name='trip_create'),
    path('trip/<int:trip_id>',trip_get,name='trip_get'),
    path('update_trip/<int:trip_id>',trip_update,name='trip_update'),
    path('delete_trip/<int:trip_id>',trip_delete,name='trip_delete'),
    path('booking_list',booking_list,name='booking_list'),
    path('booking_create',booking_create,name='booking_create'),
    path('booking/<int:booking_id>',booking_get,name='booking_get'),
    path('update_booking/<int:booking_id>',booking_update,name='booking_update'),
    path('delete_booking/<int:booking_id>',booking_delete,name='booking_delete')
    
]
