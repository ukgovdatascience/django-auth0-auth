from django.contrib.auth.decorators import login_required
from django.shortcuts import render


def js_login(request):
    return render(request, 'js-login.html')


@login_required
def login_successful(request):
    return render(request, 'login-successful.html')
