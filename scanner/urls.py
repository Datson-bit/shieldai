from django.urls import path
from .views import ScanURLView, HealthCheckView, TelegramWebhookView, AnalyseEmailView

urlpatterns = [
    path("scan/", ScanURLView.as_view(), name="scan-url"),
    path("health/", HealthCheckView.as_view(), name="health-check"),
    path("telegram/", TelegramWebhookView.as_view(), name="telegram-webhook"),
    path("analyse-email/", AnalyseEmailView.as_view(), name="analyse-email"),
]
