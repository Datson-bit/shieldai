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


class ScanURLView(APIView):

    def post(self, request):
        serializer = ScanRequestSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {"error": "Invalid URL provided.", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        url = serializer.validated_data["url"]

        # Run all checks
        url_analysis    = analyse_url(url)
        virustotal      = check_virustotal(url)
        domain_age      = check_domain_age(url)
        safe_browsing   = check_safe_browsing(url)
        gemini          = analyse_with_gemini(url)

        # Calculate final risk score
        result = calculate_risk(
            url_analysis,
            virustotal,
            domain_age,
            safe_browsing,
            gemini,
        )

        return Response(result, status=status.HTTP_200_OK)
