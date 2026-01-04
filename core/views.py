from django.shortcuts import render, redirect

def home(request):
    if request.user.is_authenticated:
        from accounts.views import get_role_redirect_url
        return redirect(get_role_redirect_url(request.user))

    return render(request, 'core/home_public.html')




#public course list view
def course_list(request):
    return render(request, 'core/course_list.html')

#public about page
def about(request):
    return render(request, 'core/about.html')

#public teacher
def teachers(request):
    return render(request, 'core/teachers.html') 

# course details
def course_detail(request):
    return render(request, 'core/course_detail.html') 

# teacher profile
def teacher_profile(request):
    return render(request, 'core/teacher_profile.html')

# contact page
def contact(request):
    return render(request, 'core/contact.html')

