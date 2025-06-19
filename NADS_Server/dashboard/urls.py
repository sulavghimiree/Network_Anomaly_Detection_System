from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('api/data/', views.get_attack_data, name='attack_data'),
    path('api/logs/', views.get_attack_logs, name='attack_logs'),
    path('predict/', views.predict_view, name='predict_view'),
    path('api/daily-stats/', views.get_daily_stats, name='daily_stats'),
]