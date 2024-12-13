from django import forms
from .models import CustomUser


#用于用户注册
class UserRegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ['name', 'username', 'password', 'email']

    def clean_username(self):
        username = self.cleaned_data['username']
        if CustomUser.objects.filter(username=username).exists():
            raise forms.ValidationError("Username is already taken.")
        return username

    def clean_email(self):
        email = self.cleaned_data['email']
        return email
#用于修改联系方式
class ChangeContactInformationForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['email']

#用于CSR文件上传
class CSRForm(forms.Form):
    csr_file = forms.FileField(required=True)
