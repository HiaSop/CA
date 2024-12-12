import OpenSSL
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import make_password
from django.core.files.storage import FileSystemStorage
from django.shortcuts import render, redirect
from django.http import JsonResponse
from .forms import CSRForm
from OpenSSL import crypto
from server.forms import UserRegistrationForm


# Create your views here.
def start(request):
    return render(request, 'server/login.html')

def user_login(request):
    if request.method == "GET":
        return render(request, 'server/login.html')
    elif request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # 使用Django的身份验证系统验证用户
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # 登录用户
            login(request, user)
            request.session["name"] = user.username  # 存储用户名到会话
            return render(request, 'server/homepage.html')  # 登录成功后重定向到主页
        else:
            # 如果用户名或密码错误，返回登录页面并显示错误信息
            return render(request, 'server/login.html', {"error": "账户或密码错误"})

def user_register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)  # 获取表单数据但不保存到数据库
            user.password = make_password(user.password)  # 哈希存储密码
            user.save()  # 现在保存到数据库
            return redirect('/login/')  # 注册成功后跳转到登录页面
    else:
        form = UserRegistrationForm()
    return render(request, 'server/register.html', {'form': form})


def upload_csr(request):
    if request.method == 'POST' and request.FILES['csr_file']:
        csr_file = request.FILES['csr_file']

        # 使用 FileSystemStorage 保存上传的 CSR 文件
        fs = FileSystemStorage()
        filename = fs.save(csr_file.name, csr_file)
        uploaded_file_url = fs.url(filename)

        # 在这里进行进一步的 CSR 验证和处理，例如解析文件、验证内容等
        # 假设验证成功，返回成功的 JSON 响应
        response_data = {
            'status': 'success',
            'message': f'文件上传成功，文件保存为 {uploaded_file_url}'
        }
        return JsonResponse(response_data)

    # 如果没有上传文件或请求不是 POST，返回失败
    return JsonResponse({'status': 'error', 'message': '没有上传文件或请求无效'})
