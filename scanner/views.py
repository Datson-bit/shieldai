from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .serializers import ScanRequestSerializer
from .services.url_analyser import analyse_url
from .services.virustotal import check_virustotal
from .services.whois_check import check_domain_age
from .services.safe_browsing import check_safe_browsing
from .services.gemini_analyser import analyse_with_gemini
from .services.scorer import calculate_risk
from concurrent.futures import ThreadPoolExecutor, as_completed

# from twilio.twiml.messaging_response import MessagingResponse
# from django.http import HttpResponse
# from django.views.decorators.csrf import csrf_exempt
# from django.utils.decorators import method_decorator
import json
from django.http import JsonResponse

# Define a shared thread pool at the module level to avoid the overhead of spawning/destroying threads per request.
# 16 workers is a sensible default for I/O-bound security scanner API requests.
scanner_executor = ThreadPoolExecutor(max_workers=16)


class ScanURLView(APIView):
    def post(self, request):
        serializer = ScanRequestSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {"error": "Invalid URL provided.", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        url = serializer.validated_data["url"]

        # Run URL analyser instantly — no API needed
        url_analysis = analyse_url(url)

        # Run all external API calls simultaneously using the shared executor
        futures = {
            scanner_executor.submit(check_virustotal, url): "virustotal",
            scanner_executor.submit(check_domain_age, url): "domain_age",
            scanner_executor.submit(check_safe_browsing, url): "safe_browsing",
            scanner_executor.submit(analyse_with_gemini, url): "gemini",
        }

        results = {}
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as e:
                results[key] = {
                    "status": "ERROR",
                    "score": 0,
                    "note": f"{key} check failed: {str(e)}",
                }

        result = calculate_risk(
            url_analysis,
            results.get("virustotal", {}),
            results.get("domain_age", {}),
            results.get("safe_browsing", {}),
            results.get("gemini", {}),
        )

        return Response(result, status=status.HTTP_200_OK)


class HealthCheckView(APIView):
    def get(self, request):
        return Response({"status": "ok", "service": "ShieldAI PhishGuard"})


class TelegramWebhookView(APIView):
    def post(self, request):
        try:
            import asyncio
            from  scanner.services.telegram_bot import get_telegram_app
            from telegram import Update

            app = get_telegram_app()
            if not app:
                return JsonResponse({"error": "Bot not configured"}, status=500)

            update = Update.de_json(
                json.loads(request.body.decode("utf-8")), app.bot
            )

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(app.process_update(update))
            loop.close()

            return JsonResponse({"status": "ok"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)