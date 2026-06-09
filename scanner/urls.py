from django.urls import path
from .views import ScanURLView, HealthCheckView

urlpatterns = [
    path("scan/", ScanURLView.as_view(), name="scan-url"),
    path("health/", HealthCheckView.as_view(), name="health-check"),

]
