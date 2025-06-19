from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from ml_model.predict import predict_intrusion
import json
from django.utils import timezone
from .models import AttackLog
from django.http import JsonResponse, HttpResponse
from datetime import timedelta

def dashboard(request):
    return render(request, 'dashboard.html')

def get_attack_data(request):
    """Get 5-minute attack data for the live graph"""
    now = timezone.now()
    five_minutes_ago = now - timedelta(minutes=5)
    logs = AttackLog.objects.filter(timestamp__gte=five_minutes_ago)
    
    attack_data = {
        'labels': [],
        'DDOS': [],
        'PortScan': [],
        'SqlInjection': [],
        'BruteForce': [],
        'Normal': [],
    }
    
    interval = timedelta(seconds=20)  # 20-second intervals
    current = five_minutes_ago
    while current < now:
        next_interval = current + interval
        attack_data['labels'].append(current.strftime("%H:%M:%S"))
        for attack_type in ['DDOS', 'PortScan', 'SqlInjection', 'BruteForce', 'Normal']:
            count = logs.filter(attack=attack_type, timestamp__gte=current, timestamp__lt=next_interval).count()
            attack_data[attack_type].append(count)
        current = next_interval
    
    return JsonResponse(attack_data)

def get_daily_stats(request):
    """Get daily attack statistics for the status cards"""
    now = timezone.now()
    one_day_ago = now - timedelta(days=1)
    logs = AttackLog.objects.filter(timestamp__gte=one_day_ago)
    
    daily_counts = {}
    for attack_type in ['DDOS', 'PortScan', 'SqlInjection', 'BruteForce', 'Normal']:
        daily_counts[attack_type] = logs.filter(attack=attack_type).count()
    
    return JsonResponse({'daily_counts': daily_counts})

def get_attack_logs(request):
    """Get attack logs for the incident log section"""
    now = timezone.now()
    one_day_ago = now - timedelta(days=1)  # Keep logs for 24 hours
    logs = AttackLog.objects.filter(timestamp__gte=one_day_ago).exclude(attack='Normal').order_by('-timestamp')
    total_attacks = logs.count()
    logs_data = [
        {
            'timestamp': log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            'host_ip': log.host_ip,
            'destination_ip': log.destination_ip,
            'attack': log.attack
        } for log in logs
    ]
    return JsonResponse({'logs': logs_data, 'total_attacks': total_attacks})

@csrf_exempt
def predict_view(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            predict_intrusion(data)
        except ValueError as e:
            print("ValueError:", e)
        return HttpResponse(status=204)
    return HttpResponse(status=405)
