from django.db import models
from django.contrib.auth.models import User
import datetime

class Admin(models.Model):
    status = [
        ('active','Active'),
        ('inactive','Inactive')
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)  
    email = models.EmailField(max_length=150)
    # password = models.CharField(max_length=128)
    status = models.CharField(max_length=15, choices = status)


    

class Manager(models.Model):
    state = [
       ('active','Active'),
        ('inactive','Inactive')
    ] 
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=150)
    # password = models.CharField(max_length=128)
    status = models.CharField(max_length=15, choices = state,default='active')

    

class Employee(models.Model):
    status = [
        ('active','Active'),
        ('inactive','Inactive')
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # name = models.CharField(max_length=100)
    name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50, null=True, blank=True)
    email = models.EmailField(max_length=150)
    status = models.CharField(max_length=15, choices = status)
    manager = models.ForeignKey(Manager,on_delete=models.SET_NULL,null=True)

class TravelRequests(models.Model):

    status = [

        ('pending','Pending'),
        ('approved','Approved'),
        ('rejected','Rejected'),
        ('resubmit','Resubmit'),
        ('closed','Closed'),
        ('deleted','Deleted'),
        ('resubmitted','Resubmitted')
    ]

    modes = [
        ('train','Train'),
        ('air','Air'),        
        ('car','Car'),
        ('bus','Bus'),
        ('ship','Ship')

    ]

    employee = models.ForeignKey(Employee,on_delete=models.SET_NULL,null=True,related_name="travel_requests")
    manager = models.ForeignKey(Manager,on_delete=models.SET_NULL,null=True, related_name="managed_travel_requests")
    from_location = models.CharField(max_length=100)
    to_location = models.CharField(max_length=100)
    date_submitted = models.DateTimeField(auto_now_add=True)
    from_date = models.DateField()
    to_date = models.DateField()
    islodging_needed = models.BooleanField(default=False)
    accommodation_name = models.CharField(max_length=100, null=True, blank=True)
    accommodation_type = models.CharField(max_length=25, null=True, blank=True)
    travel_mode = models.CharField(max_length=30,choices=modes)
    purpose = models.TextField()
    additional_note = models.CharField(max_length=2000,null=True,blank=True)
    manager_note = models.CharField(max_length=2000,null=True,blank=True)
    admin_note = models.CharField(max_length=2000,null=True,blank=True)
    updatereq_asked_by_manager = models.CharField(max_length=2000,null=True,blank=True)
    updatereq_asked_by_admin = models.CharField(max_length=2000,null=True,blank=True)
    status = models.CharField(max_length=20, choices=status,default="pending")
    approval_date = models.DateTimeField(null=True)
    rejected_date = models.DateTimeField(null=True)
    close_date = models.DateTimeField(null=True)
    resubmitted = models.BooleanField(default=False)  







    



