from django.db import models


# Create your models here.
class BaseModel(models.Model):
    """
    Base models to save the common properties such as:
        created_at, updated_at, created_at, updated_at is_deleted, deleted_at.
    """
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Created At')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='Last Updated At')

    class Meta:
        abstract = True
        verbose_name = 'BaseModel'
        indexes = [
            models.Index(fields=["created_at", "updated_at"]),
        ]
