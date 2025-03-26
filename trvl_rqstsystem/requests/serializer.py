from . import models
from rest_framework import serializers

class AdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Admin
        fields = '__all__'

class ManagerSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Manager
        fields = '__all__'

class EmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Employee
        fields = '__all__'

class RequestSerializerEmployee(serializers.ModelSerializer):
    class Meta:
        model = models.TravelRequests
        fields = ['name', 'last_name', 'from_location', 'to_location', 'date_submitted', 'from_date', 'status']

class RequestSerializerManager(serializers.ModelSerializer):
    employee = EmployeeSerializer()
    name = serializers.CharField(source="employee.name", read_only=True)
    last_name = serializers.CharField(source="employee.last_name", read_only=True)

    class Meta:
        model = models.TravelRequests
        fields = ['id', 'name', 'last_name', 'from_location', 'to_location', 'date_submitted', 'from_date', 'to_date', 'status', 'employee']

class RequestSerializerAdmin(serializers.ModelSerializer):
    employee = EmployeeSerializer()
    manager = ManagerSerializer()
    name = serializers.CharField(source="employee.name", read_only=True)
    last_name = serializers.CharField(source="employee.last_name", read_only=True)
    
    # Add missing fields explicitly
    travel_mode = serializers.CharField()
    islodging_needed=serializers.BooleanField
    accommodation_name = serializers.CharField()
    accommodation_type = serializers.CharField()
    purpose = serializers.CharField()
    additional_note = serializers.CharField()

    class Meta:
        model = models.TravelRequests
        fields = ['id', 'name', 'last_name', 'from_location', 'to_location', 'date_submitted', 
                  'from_date', 'to_date', 'status', 'travel_mode', 'islodging_needed', 'accommodation_name', 
                  'accommodation_type', 'purpose', 'additional_note', 'employee', 'manager']


class TravelSerializer(serializers.ModelSerializer):
    employee = EmployeeSerializer()
    manager = ManagerSerializer()
    name = serializers.CharField(source="employee.name", read_only=True)
    last_name = serializers.CharField(source="employee.last_name", read_only=True)

    class Meta:
        model = models.TravelRequests
        fields = '__all__'  # Keep everything, including name and last_name

class NewTravelSerializer(serializers.ModelSerializer):
    """Serializer for POST/PUT (Uses only Employee & Manager IDs)"""
    
    class Meta:
        model = models.TravelRequests
        fields = '__all__'

    def create(self, validated_data):
        employee = validated_data.get("employee")

        # Auto-assign manager if not already provided, ensuring it doesn't break
        if employee and not validated_data.get("manager") and hasattr(employee, 'manager'):
            validated_data["manager"] = employee.manager  

        return super().create(validated_data)
