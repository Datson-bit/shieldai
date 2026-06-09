from rest_framework import serializers


class ScanRequestSerializer(serializers.Serializer):
    url = serializers.URLField()
