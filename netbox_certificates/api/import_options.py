from rest_framework import serializers
from users.models import Owner

from ..models import ArtifactGroup
from ..permissions import action_queryset


class ImportOptionsSerializer(serializers.Serializer):
    owner = serializers.PrimaryKeyRelatedField(queryset=Owner.objects.none(), required=False, allow_null=True)
    groups = serializers.PrimaryKeyRelatedField(queryset=ArtifactGroup.objects.none(), many=True, required=False)
    password = serializers.CharField(required=False, allow_blank=True, write_only=True, trim_whitespace=False)
    archive_password = serializers.CharField(required=False, allow_blank=True, write_only=True, trim_whitespace=False)
    import_chain = serializers.BooleanField(default=True)
    preserve_archive = serializers.BooleanField(default=True)
    ca_only = serializers.BooleanField(default=False)
    description = serializers.CharField(required=False, allow_blank=True, max_length=200)
    comments = serializers.CharField(required=False, allow_blank=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get("request")
        if request is None:
            return
        user = request.user
        self.fields["owner"].queryset = Owner.objects.all() if user.is_superuser else Owner.objects.filter(users=user)
        self.fields["groups"].child_relation.queryset = action_queryset(ArtifactGroup, user, "view")


class ImportRequestSerializer(ImportOptionsSerializer):
    files = serializers.ListField(child=serializers.FileField(), allow_empty=False, write_only=True)
