from django.db import models
from django.contrib.auth.models import AbstractBaseUser, UserManager, BaseUserManager

# Create your models here.
from core.models import BaseModel


class MyUserManager(BaseUserManager):
    """
    Inherits: BaseUserManager class
    """

    def create_user(self, email, password=None):
        """
        Create user with given email and password.
        :param email:
        :param password:
        :return:
        """
        if not email:
            raise ValueError('Users must have an email address')
        user = self.model(email=self.normalize_email(email))
        # set_password is used set password in encrypted form.
        user.set_password(password)
        user.is_active = True
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        """
        Create and save the superuser with given email and password.
        :param email:
        :param password:
        :return: user
        """
        user = self.create_user(email, password=password)
        user.is_superuser = True
        user.username = ""
        user.is_staff = True
        user.is_active = True
        user.save(using=self._db)
        return user


class ActiveUserManager(UserManager):
    """
        ActiveUserManager class to filter the deleted user.
    """
    def get_queryset(self):
        return super(ActiveUserManager, self).get_queryset().filter(is_active=True, is_deleted=False)


class ActiveObjectsManager(UserManager):
    """
        ActiveObjectsManager class to filter the deleted objs
    """
    def get_queryset(self):
        return super(ActiveObjectsManager, self).get_queryset().filter(is_deleted=False)


class User(AbstractBaseUser, BaseModel):
    """
    User models used for the authentication process, and it contains basic
     fields.
     Inherit : AbstractBaseUser, PermissionMixin, BaseModel
    """

    class RoleType(models.IntegerChoices):
        """
            VerificationType Models used for the token_type
        """
        SUPER_ADMIN_USER = 1
        NORMAL_USER = 2
        ADMIN_USER = 3

    email = models.EmailField(max_length=120, db_index=True, blank=False,
                              null=False, verbose_name='Email')
    first_name = models.CharField(max_length=50, blank=True, null=True, verbose_name='First Name')
    last_name = models.CharField(max_length=50, blank=True, null=True, verbose_name='Last Name')
    role = models.IntegerField(choices=RoleType.choices, default=2, verbose_name='Gender')
    is_active = models.BooleanField(default=True, verbose_name='Is Active')
    is_deleted = models.BooleanField(default=False, verbose_name='Is Deleted')
    is_staff = models.BooleanField(default=False, verbose_name='Is Staff')
    is_superuser = models.BooleanField(default=False, verbose_name='Is SuperUser')

    objects = ActiveUserManager()
    all_objects = ActiveObjectsManager()
    all_delete_objects = UserManager()
    my_user_manager = MyUserManager()
    USERNAME_FIELD = 'id'

    def has_perm(self, perm, obj=None):
        """
        has_perm method used to give permission to the user.
        :param perm:
        :param obj:
        :return: is_staff
        """
        return self.is_staff

    def has_module_perms(self, app_label):
        """
        method to give module permission to the superuser.
        :param app_label:
        :return: is_superuser
        """
        return self.is_superuser

    def __str__(self):
        """
        :return: email
        """
        return "{0}-({1})".format(self.email, self.pk)

    def get_short_name(self):
        return self.email

    class Meta:
        verbose_name = 'User'
        db_table = 'user'
        ordering = ['id']
        indexes = models.Index(fields=["email", "updated_at"]),


class UserPermission(models.Model):
    """ UserPermission
            Defines the model used to store the User Permission for Business Group, Category,
            Business Unit & Country.
        Inherits : `models.Model`
    """
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name='user_permission_ref',
                             verbose_name='User Obj')
    business_group = models.TextField(default='ALL', verbose_name='Business Group List')
    category = models.TextField(default='ALL', verbose_name='Category List')
    business_unit = models.TextField(default='ALL', verbose_name='Business Unit List')
    country = models.TextField(default='ALL', verbose_name='Country List')

    objects = models.Manager()

    class Meta:
        verbose_name = 'UserPermission'
        db_table = 'user_permission'
