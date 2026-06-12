from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("scanner.urls")),
    path("app/", RedirectView.as_view(url="/static/phishguard/index.html")),
    path("", RedirectView.as_view(url="/static/phishguard/landing_page.html")),
]
