from django.urls import path
from .views import ScanURLView

urlpatterns = [
    path("scan/", ScanURLView.as_view(), name="scan-url"),
]
