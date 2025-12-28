from django.shortcuts import render
from django.http import HttpResponse

# Create your views here.

def home(request):
    """Simple home page view"""
    return render(request, 'courses/home.html')

