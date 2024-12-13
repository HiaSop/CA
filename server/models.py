from django.contrib.auth.models import AbstractUser  # 导入Django的AbstractUser类，用于扩展用户模型
from django.db import models  # 导入Django的模型模块，用于定义数据表


# 自定义用户模型，继承自AbstractUser，可以扩展默认的User模型
class CustomUser(AbstractUser):
    # 重写 username 字段的验证器，最大长度为8，且每个用户名必须唯一
    username = models.CharField(
        max_length=8,  # 限制最大长度为8
        unique=True,  # 确保用户名唯一
        verbose_name="账号"  # 为此字段提供一个更友好的名称
    )

    # 用户的姓名，最大长度为20
    name = models.CharField(max_length=20, verbose_name="名字")

    def __str__(self):
        # 重写__str__方法，当打印用户实例时显示用户名
        return self.username


# 证书模型
class Certificate(models.Model):
    # 外键关联到 CustomUser 的 username 字段，确保每个证书都属于某个用户
    user = models.ForeignKey(
        CustomUser,  # 关联到CustomUser模型
        related_name='certificates',  # 在CustomUser模型中通过certificates访问所有证书
        on_delete=models.CASCADE,  # 如果用户被删除，则对应的证书也会被删除
        verbose_name="用户"  # 字段的名称，显示为“用户”
    )

    # 公共名（即证书申请中的 CN 字段）
    common_name = models.CharField(max_length=255, verbose_name="公共名")

    # 存储公钥，类型为文本
    public_key = models.TextField(verbose_name="公钥")

    # 证书序列号，唯一
    serial_number = models.CharField(max_length=64, unique=True, verbose_name="序列号")

    # 签发时间，自动记录证书创建时间
    issued_at = models.DateTimeField(auto_now_add=True, verbose_name="签发时间")

    # 证书的过期时间
    expires_at = models.DateTimeField(verbose_name="过期时间")

    # 证书的状态，包含有效、已注销和已过期三种状态
    status = models.CharField(
        max_length=10,  # 状态字段的最大长度为10
        choices=[  # 提供三个选择项：有效、已注销、已过期
            ("valid", "有效"),  # 状态为“有效”
            ("revoked", "已注销"),  # 状态为“已注销”
            ("expired", "已过期"),  # 状态为“已过期”
        ],
        default="valid",  # 默认状态为“有效”
        verbose_name="状态"  # 字段的名称，显示为“状态”
    )

    # 新增字段：证书存储位置，存储证书存放的路径或位置
    storage_location = models.CharField(
        max_length=255,  # 存储位置的最大长度为255
        verbose_name="证书存储位置",  # 字段的名称，显示为“证书存储位置”
        null=True,  # 可以为空
        blank=True  # 在表单中可以为空
    )

    def __str__(self):
        # 重写__str__方法，打印证书的公共名和状态
        return f"Certificate: {self.common_name} ({self.status})"
