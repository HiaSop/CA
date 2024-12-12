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

