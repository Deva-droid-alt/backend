from rest_framework.permissions import BasePermission

class IsManager(BasePermission):
    
    def has_permission(self, request, view):
            user = hasattr(request.user,'manager')
            return user
    # ,request.user.id

# class IsEmployee(BasePermission):
      
#     def has_permission(self, request, view):
#         user = hasattr(request.user,'employee')
#         return user

class IsEmployee(BasePermission):
    """Permission class to check if the user is an Employee."""

    def has_permission(self, request, view):
        # Ensure the user is authenticated and has a related Employee object
        return bool(request.user and request.user.is_authenticated and hasattr(request.user, 'employee') and request.user.employee)
    
class IsAdmin(BasePermission):
      
    def has_permission(self, request, view):
        user = hasattr(request.user,'admin')
        return user