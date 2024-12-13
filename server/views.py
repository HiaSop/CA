import datetime
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect
from django.http import JsonResponse
import requests
from django.views.decorators.csrf import csrf_exempt
from server.forms import UserRegistrationForm
from server.models import CustomUser, Certificate


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
            print(user.username)
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

@login_required
@csrf_exempt
def upload_csr(request):
    user = request.user
    if request.method == "POST":
        try:
            # 获取上传的文件
            csr_file = request.FILES.get("csr_file")
            if not csr_file:
                return JsonResponse({"error": "CSR file is required."}, status=400)

            # 读取文件内容
            csr_content = csr_file.read()

            # 调用 CA 签发证书的 API
            ca_api_url = "http://127.0.0.1:8000/api/sign_csr"
            response = requests.post(ca_api_url, files={"csr_file": csr_content}, data={"user_id": user.id})

            # 检查 API 响应
            if response.status_code == 200:
                return JsonResponse(response.json())
            else:
                return JsonResponse({"error": "CA API error", "details": response.text}, status=response.status_code)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return render(request, "server/upload_csr.html")


@csrf_exempt
def sign_csr(request):
    if request.method == "POST":
        try:
            # 获取CSR文件内容
            csr_data = request.FILES.get("csr_file")
            user_id = request.POST.get("user_id")  # 从请求中获取 user_id
            user = CustomUser.objects.get(id=user_id)

            if not csr_data:
                return JsonResponse({"error": "CSR file is required."}, status=400)

            # 读取CSR内容并解析
            csr = x509.load_pem_x509_csr(csr_data.read())

            # 校验CSR文件的合法性
            if not csr.is_signature_valid:
                return JsonResponse({"error": "Invalid CSR signature."}, status=400)

            # 签发证书
            ca_key_path = os.path.join(settings.BASE_DIR, "templates", "ca", "ca_key.pem")
            ca_cert_path = os.path.join(settings.BASE_DIR, "templates", "ca", "ca_cert.pem")


            with open(ca_key_path, "rb") as key_file, open(ca_cert_path, "rb") as cert_file:
                ca_key = load_pem_private_key(key_file.read(), password=None)
                ca_cert = x509.load_pem_x509_certificate(cert_file.read())

            issued_cert = (
                x509.CertificateBuilder()
                .subject_name(csr.subject)
                .issuer_name(ca_cert.subject)
                .public_key(csr.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(private_key=ca_key, algorithm=hashes.SHA256())
            )

            # 保存
            cert_path = os.path.join(settings.BASE_DIR+"/templates/certificates")
            serial_number = issued_cert.serial_number     # 提取序列号
            with open(cert_path + f"/{serial_number}.cer", mode='wb') as cert_file:
                cert_file.write(issued_cert.public_bytes(encoding=serialization.Encoding.PEM))

            print(user.username)
            # 保存信息到数据库
            cert = Certificate(
                user=user,
                common_name=csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
                public_key=csr.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8'),
                serial_number=str(issued_cert.serial_number),
                issued_at=datetime.datetime.utcnow(),
                expires_at=datetime.datetime.utcnow() + datetime.timedelta(days=365),
                status='valid',  # 默认状态为有效
                storage_location=cert_path  # 保存证书所在地址
            )
            cert.save()

            return JsonResponse({"message": "Certificate issued successfully.", "certificate_path": cert_path})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid HTTP method."}, status=405)

@csrf_exempt
def verify_certificate(request):
    if request.method == "POST":
        try:
            # 获取证书文件内容
            cert_data = request.FILES.get("certificate_file")
            if not cert_data:
                return JsonResponse({"error": "Certificate file is required."}, status=400)

            # 读取证书内容并解析
            cert = x509.load_pem_x509_certificate(cert_data.read(), default_backend())

            # 获取CA证书路径
            ca_cert_path = os.path.join(settings.BASE_DIR, "templates/ca/ca_cert.pem")

            with open(ca_cert_path, "rb") as cert_file:
                ca_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

            # 验证证书签名
            public_key = ca_cert.public_key()
            try:
                # 使用CA证书的公钥验证签名
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            except Exception as e:
                return JsonResponse({"error": f"Certificate signature verification failed: {str(e)}"}, status=400)

            # 验证证书的有效期
            if cert.not_valid_before > datetime.datetime.utcnow() or cert.not_valid_after < datetime.datetime.utcnow():
                return JsonResponse({"error": "Certificate is expired or not yet valid."}, status=400)

            # 证书的颁发者和主题一致性
            if cert.issuer != ca_cert.subject:
                return JsonResponse({"error": "Certificate issuer does not match the CA."}, status=400)

            return JsonResponse({"message": "Certificate is valid."})

        except Exception as e:
            return JsonResponse({"error": f"Verification failed: {str(e)}"}, status=500)
    else:
        return JsonResponse({"error": "Invalid HTTP method."}, status=405)
