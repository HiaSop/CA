import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect
import requests
from django.views.decorators.csrf import csrf_exempt
from server.forms import UserRegistrationForm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import Name, NameAttribute
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import CertificateSigningRequestBuilder
from cryptography.hazmat.primitives import hashes
from django.http import JsonResponse
from django.shortcuts import render
import os
from server.models import CustomUser, Certificate
from django.utils import timezone
# 默认界面
def start(request):
    if request.user.is_authenticated:
        return render(request, 'server/homepage.html')  # 登录成功后重定向到主页
    return redirect('login')


def homepage(request):
    return render(request, 'server/homepage.html')

#登录界面
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
            return redirect('/homepage/')  # 登录成功后重定向到主页
        else:
            # 如果用户名或密码错误，返回登录页面并显示错误信息
            return render(request, 'server/login.html', {"error": "账户或密码错误"})

#注册界面
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

#上传CSR文件
@csrf_exempt
def upload_csr(request):
    if request.method == "POST":  # 如果请求方法是POST
        try:
            # 获取上传的文件
            csr_file = request.FILES.get("csr_file")  # 获取上传的CSR文件
            if not csr_file:  # 如果没有上传CSR文件
                return JsonResponse({"error": "CSR file is required."}, status=400)  # 返回400错误，提示缺少CSR文件

            # 读取文件内容
            csr_content = csr_file.read()  # 读取上传的文件内容

            # 调用 CA 签发证书的 API
            ca_api_url = "http://127.0.0.1:8001/api/sign_csr"  # 定义CA签发证书的API接口地址
            response = requests.post(ca_api_url, files={"csr_file": csr_content})  # 通过POST请求将CSR文件传递给CA的API接口

            # 检查 API 响应
            if response.status_code == 200:  # 如果API响应成功（200 OK）
                return JsonResponse(response.json())  # 返回API的响应内容（签发证书结果）
            else:
                return JsonResponse({"error": "CA API error", "details": response.text}, status=response.status_code)  # 如果响应失败，返回错误信息

        except Exception as e:  # 捕获任何异常
            return JsonResponse({"error": str(e)}, status=500)  # 返回异常信息

    else:  # 如果请求方法不是POST
        return render(request, "server/upload_csr.html")  # 返回上传CSR文件的页面


#签发证书
@csrf_exempt
def sign_csr(request):
    if request.method == "POST":  # 如果请求方法是POST
        try:
            # 获取CSR文件内容
            csr_data = request.FILES.get("csr_file")  # 获取上传的CSR文件
            if not csr_data:  # 如果没有上传CSR文件
                return JsonResponse({"error": "CSR file is required."}, status=400)  # 返回400错误，提示缺少CSR文件

            # 读取CSR内容并解析
            csr = x509.load_pem_x509_csr(csr_data.read())  # 解析CSR文件内容，返回一个CSR对象

            # 校验CSR文件的合法性
            if not csr.is_signature_valid:  # 检查CSR的签名是否有效
                return JsonResponse({"error": "Invalid CSR signature."}, status=400)  # 如果签名无效，返回400错误

            # 签发证书
            ca_key_path = os.path.join(settings.BASE_DIR, "templates", "ca", "ca_key.pem")  # 获取CA私钥文件路径
            ca_cert_path = os.path.join(settings.BASE_DIR, "templates", "ca", "ca_cert.pem")  # 获取CA证书文件路径

            # 读取CA的私钥和证书
            with open(ca_key_path, "rb") as key_file, open(ca_cert_path, "rb") as cert_file:
                ca_key = load_pem_private_key(key_file.read(), password=None)  # 加载CA私钥
                ca_cert = x509.load_pem_x509_certificate(cert_file.read())  # 加载CA证书

            # 创建签发的证书
            issued_cert = (
                x509.CertificateBuilder()
                .subject_name(csr.subject)  # 设置证书的主体名称为CSR的主体名称
                .issuer_name(ca_cert.subject)  # 设置证书的颁发者为CA证书的主体名称
                .public_key(csr.public_key())  # 设置证书的公钥为CSR中的公钥
                .serial_number(x509.random_serial_number())  # 生成随机的证书序列号
                .not_valid_before(datetime.datetime.utcnow())  # 设置证书的生效时间为当前时间
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 设置证书的过期时间为1年后
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)  # 添加基本约束，非CA证书
                .sign(private_key=ca_key, algorithm=hashes.SHA256())  # 使用CA的私钥和SHA256算法进行签名
            )

            # 保存证书
            cert_path = os.path.join(settings.BASE_DIR + "/templates/certificates")  # 获取保存证书的路径
            serial_number = issued_cert.serial_number  # 获取证书的序列号

            # 将证书保存为PEM和CER格式
            with open(cert_path + f"/{serial_number}.cer", mode='wb') as cert_file:
                cert_file.write(issued_cert.public_bytes(serialization.Encoding.PEM))  # 保存为CER格式
            with open(cert_path + f"/{serial_number}.pem", "wb") as cert_file:
                cert_file.write(issued_cert.public_bytes(encoding=serialization.Encoding.PEM))  # 保存为PEM格式

            return JsonResponse({"message": "Certificate issued successfully.", "certificate_path": cert_path})  # 返回证书签发成功的信息
        except Exception as e:  # 捕获任何异常
            return JsonResponse({"error": str(e)}, status=500)  # 返回异常信息

    else:  # 如果请求方法不是POST
        return JsonResponse({"error": "Invalid HTTP method."}, status=405)  # 返回405错误，提示方法不允许


#验证证书
@csrf_exempt
def verify_certificate(request):
    if request.method == "POST":  # 如果请求方法是POST
        try:
            # 获取证书文件内容
            cert_data = request.FILES.get("certificate_file")  # 获取上传的证书文件
            if not cert_data:  # 如果没有上传证书文件
                return JsonResponse({"error": "Certificate file is required."}, status=400)  # 返回400错误，提示缺少证书文件

            # 读取证书内容并解析
            cert = x509.load_pem_x509_certificate(cert_data.read(), default_backend())  # 解析证书文件内容

            # 获取CA证书路径
            ca_cert_path = os.path.join(settings.BASE_DIR, "templates/ca/ca_cert.pem")

            # 读取CA证书
            with open(ca_cert_path, "rb") as cert_file:
                ca_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())  # 加载CA证书

            # 验证证书签名
            public_key = ca_cert.public_key()  # 获取CA证书的公钥
            try:
                # 使用CA证书的公钥验证签名
                public_key.verify(
                    cert.signature,  # 使用证书的签名
                    cert.tbs_certificate_bytes,  # 使用证书的原始字节
                    padding.PKCS1v15(),  # 使用PKCS#1 v1.5填充方式
                    hashes.SHA256()  # 使用SHA256算法
                )
            except Exception as e:  # 如果签名验证失败
                return JsonResponse({"error": f"Certificate signature verification failed: {str(e)}"}, status=400)

            # 验证证书的有效期
            if cert.not_valid_before > datetime.datetime.utcnow() or cert.not_valid_after < datetime.datetime.utcnow():  # 检查证书是否过期或未生效
                return JsonResponse({"error": "Certificate is expired or not yet valid."}, status=400)  # 返回证书无效的错误

            # 证书的颁发者和主题一致性
            if cert.issuer != ca_cert.subject:  # 如果证书的颁发者和CA证书的主体不一致
                return JsonResponse({"error": "Certificate issuer does not match the CA."}, status=400)  # 返回错误

            return JsonResponse({"message": "Certificate is valid."})  # 证书有效，返回成功信息

        except Exception as e:  # 捕获任何异常
            return JsonResponse({"error": f"Verification failed: {str(e)}"}, status=500)  # 返回异常信息

    else:  # 如果请求方法不是POST
        return JsonResponse({"error": "Invalid HTTP method."}, status=405)  # 返回405错误，提示方法不允许



def view_certificates(request):
    user = request.user
    certificates = Certificate.objects.filter(user=user) # 查询该用户的所有证书
    return render(request, 'server/view_certificates.html', {'certificates': certificates})

# 根据提供的消息生成CSR证书
from django.shortcuts import render

def generate_csr(request):
    try:
        user = request.username

        if not user.is_authenticated:
            return JsonResponse({"error": "User is not authenticated."}, status=401)

        # 生成RSA密钥对
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # 创建CSR（证书签名请求）
        subject = Name([
            NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            NameAttribute(NameOID.COMMON_NAME, user.username),
        ])

        csr = CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())

        # 导出CSR和私钥为PEM格式
        csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # 生成唯一证书序列号
        serial_number = os.urandom(16).hex()

        # 保存CSR文件和私钥文件
        output_dir = os.path.join(os.path.dirname(__file__), "generated_csr_files")
        os.makedirs(output_dir, exist_ok=True)

        csr_path = os.path.join(output_dir, f"{serial_number}_csr.csr")
        private_key_path = os.path.join(output_dir, f"{serial_number}_private_key.pem")

        # 保存文件
        with open(csr_path, "wb") as csr_file:
            csr_file.write(csr_pem)

        with open(private_key_path, "wb") as private_key_file:
            private_key_file.write(private_key_pem)

        # 保存证书信息到数据库
        certificate = Certificate(
            user=user,
            common_name=user.username,
            public_key=private_key.public_key(),
            serial_number=serial_number,
            issued_at=timezone.now(),
            expires_at=timezone.now() + timezone.timedelta(days=365),
            status="valid",
            storage_location=csr_path
        )
        certificate.save()

        # 返回 HTML 响应而不是 JSON
        return render(request, 'server/generate_csr.html', {
            'certificate': certificate,
            'csr_path': csr_path,
            'private_key_path': private_key_path
        })

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
