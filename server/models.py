from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    # 重写 username 字段的验证器
    username = models.CharField(
        max_length=8,
        unique=True,
        verbose_name="账号"
    )
    name = models.CharField(max_length=20, verbose_name="名字")

    def __str__(self):
        return self.username

# 证书模型
class Certificate(models.Model):
    # 外键关联到 CustomUser 的 username 字段
    user = models.ForeignKey(
        CustomUser,
        related_name='certificates',  # 反向关系名称
        on_delete=models.CASCADE,     # 如果用户被删除，证书也会被删除
        verbose_name="用户"
    )
    common_name = models.CharField(max_length=255, verbose_name="公共名")  # 公共名（证书申请的 CN 字段）
    public_key = models.TextField(verbose_name="公钥")  # 用户的公钥
    serial_number = models.CharField(max_length=64, unique=True, verbose_name="序列号")  # 证书序列号
    issued_at = models.DateTimeField(auto_now_add=True, verbose_name="签发时间")  # 签发时间
    expires_at = models.DateTimeField(verbose_name="过期时间")  # 证书过期时间

    # 状态字段
    status = models.CharField(
        max_length=10,
        choices=[
            ("valid", "有效"),          # 证书有效
            ("revoked", "已注销"),      # 证书已注销
            ("expired", "已过期"),      # 证书已过期
        ],
        default="valid",
        verbose_name="状态"
    )

    # 新增字段：证书存储位置
    storage_location = models.CharField(
        max_length=255,
        verbose_name="证书存储位置",
        null=True,
        blank=True
    )

    def __str__(self):
        return f"Certificate: {self.common_name} ({self.status})"