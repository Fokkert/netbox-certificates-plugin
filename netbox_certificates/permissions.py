STANDARD_ACTIONS = {"view", "add", "change", "delete"}


def permission_name(model, action):
    model_name = model._meta.model_name
    custom = {
        ("certificate", "download"): "download_certificate",
        ("privatekey", "download"): "download_privatekey",
        ("csr", "download"): "download_csr",
        ("bundle", "export"): "export_bundle",
        ("bundle", "export_pfx"): "export_pfx_bundle",
        ("expiryalertconfiguration", "test"): "test_expiryalertconfiguration",
    }
    codename = custom.get((model_name, action), f"{action}_{model_name}")
    return f"{model._meta.app_label}.{codename}"


def action_queryset(model, user, action="view"):
    qs = model.objects.all()
    if not getattr(user, "is_authenticated", False):
        return qs.none()
    if getattr(user, "is_superuser", False):
        return qs
    if not user.has_perm(permission_name(model, action)):
        return qs.none()
    restrict_action = action if action in STANDARD_ACTIONS else "view"
    if hasattr(qs, "restrict"):
        return qs.restrict(user, restrict_action)
    return qs


def object_allowed(user, obj, action="view"):
    if obj is None or not getattr(user, "is_authenticated", False):
        return False
    if getattr(user, "is_superuser", False):
        return True
    model = obj.__class__
    if not user.has_perm(permission_name(model, action)):
        return False
    restrict_action = action if action in STANDARD_ACTIONS else "view"
    manager = getattr(model, "objects", None)
    if manager is not None and hasattr(manager, "restrict"):
        return manager.restrict(user, restrict_action).filter(pk=obj.pk).exists()
    return True
