from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from ml_model.predict import predict_intrusion
import json
from django.http import HttpResponse
# Create your views here.

def dashboard(request):
    return render(request, 'dashboard.html')

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
