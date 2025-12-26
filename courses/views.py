from django.shortcuts import render
from django.http import HttpResponse

# Create your views here.

def home(request):
    """Simple home page view"""
    return HttpResponse("<h1>Welcome to Siksha Setu</h1><p>E-Learning Platform</p>")
