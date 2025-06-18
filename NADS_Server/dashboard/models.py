from django.db import models

# Create your models here.

class AttackLog(models.Model):
    device_id = models.CharField(max_length=100, default='1')
    host_ip = models.GenericIPAddressField()
    destination_ip = models.GenericIPAddressField()
    attack = models.CharField(max_length=100)
    timestamp = models.DateTimeField()

    def __str__(self):
        return f"{self.attack} from {self.host_ip} to {self.destination_ip} at {self.timestamp}"