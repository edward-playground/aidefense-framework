"""Execute the live HTML examples; the fixtures are not customer deployment evidence."""
import ast
import copy
import importlib
import io
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sources = json.load(sys.stdin)
for value in sources.values():
    ast.parse(value)
now = datetime(2030, 1, 1, 12, 30, tzinfo=timezone.utc)


def rejects(call, message=None):
    try:
        call()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        if message:
            assert message in str(error), (message, error)
    else:
        raise AssertionError("unsafe input was accepted")


with tempfile.TemporaryDirectory(prefix="aidefend-reconstruction-test-") as directory:
    root = Path(directory)
    for key, name in (("runtimeSource", "reconstruction_runtime.py"),
                      ("builderSource", "build_reconstruction_reference.py"),
                      ("detectorSource", "media_reconstruction_detector.py")):
        (root / name).write_text(sources[key], encoding="utf-8", newline="\n")
    sys.path.insert(0, str(root))
    shared = importlib.import_module("reconstruction_runtime")
    detector = importlib.import_module("media_reconstruction_detector")

    def policy():
        return {
            "schema_version": "aidefend.reconstruction-policy.v2",
            "policy_version": "test-policy", "reference_version": "test-reference",
            "media_domain": "test-images", "pipeline_sha256": shared.sha256((root / "reconstruction_runtime.py").read_bytes()),
            "model_config_path": str(root / "model.json"), "model_config_sha256": "a" * 64,
            "model_weights_path": str(root / "model.pt"), "model_weights_sha256": "b" * 64,
            "preprocessing_path": str(root / "preprocessing.json"), "preprocessing_sha256": "c" * 64,
            "clean_holdout_path": str(root / "holdout.json"), "clean_holdout_sha256": "d" * 64,
            "expected_samples": 2, "minimum_samples": 2, "baseline_quantile": 0.95,
            "issued_at": "2030-01-01T12:00:00Z", "expires_at": "2030-01-01T13:00:00Z",
            "maximum_reference_age_seconds": 3600,
        }

    if sys.argv[1] == "contract":
        declaration = policy()
        runtime = SimpleNamespace(policy=declaration, policy_raw=shared.canonical(declaration))
        reference = {
            "schema_version": shared.REFERENCE_SCHEMA, "status": "PASS",
            **shared.reference_bindings(runtime), "measured_samples": 2,
            "error_metric": "mean_squared_error.float32.per_image",
            "mean_mse": 0.01, "std_mse": 0.02, "baseline_quantile": 0.95,
            "quantile_mse": 0.03, "quantile_method": "numpy.linear",
        }
        shared.validate_reference(runtime, reference, now=now)
        for key, value in (
            ("schema_version", "aidefend.reconstruction_baseline.v1"),
            ("preprocessing_sha256", "e" * 64), ("pipeline_sha256", "e" * 64),
            ("model_weights_sha256", "e" * 64), ("media_domain", "another-domain"),
            ("measured_samples", 1), ("expected_samples", True), ("mean_mse", float("nan")),
            ("error_metric", "some_other_error"), ("expires_at", "2031-01-01T00:00:00Z"),
        ):
            bad = {**reference, key: value}
            rejects(lambda: shared.validate_reference(runtime, bad, now=now))
        missing = dict(reference)
        del missing["preprocessing_sha256"]
        rejects(lambda: shared.validate_reference(runtime, missing, now=now))
        rejects(lambda: shared.validate_reference(runtime, reference,
                now=datetime(2030, 1, 1, 13, tzinfo=timezone.utc)), "not currently valid")
        rejects(lambda: shared.validate_reference(runtime, reference,
                now=datetime(2030, 1, 1, 11, tzinfo=timezone.utc)), "not currently valid")
        bad_policy = {**declaration, "expires_at": "2030-01-01T14:00:00Z"}
        rejects(lambda: shared.validate_policy(bad_policy), "validity")
        rejects(lambda: shared.strict_json(b'{"key":1,"key":2}'), "duplicate")
        rejects(lambda: shared.strict_json(b'{"key":NaN}'), "non-finite")
        print("CONTRACT_OK")

    elif sys.argv[1] == "verification":
        artifact, signature = root / "candidate.json", root / "candidate.sig"
        payload = b'{"captured":true}\n'
        artifact.write_bytes(payload)
        signature.write_bytes(b"test-signature")
        kwargs = dict(maximum_bytes=1024, command_timeout=5)
        def verify_snapshot(args, **options):
            assert args[:2] == ["cosign", "verify-blob"]
            snapshot, bundle = Path(args[-1]), Path(args[args.index("--bundle") + 1])
            assert snapshot.read_bytes() == payload
            assert bundle.read_bytes() == b"test-signature"
            artifact.write_bytes(b"changed original after capture")
            return subprocess.CompletedProcess(args, 0)
        with patch.object(shared.subprocess, "run", verify_snapshot):
            assert shared.verified_bytes(artifact, signature, "trusted-key", shared.sha256(payload), **kwargs) == payload
        rejects(lambda: shared.verified_bytes(artifact, signature, "trusted-key", shared.sha256(payload), **kwargs), "binding")
        artifact.write_bytes(payload)
        with patch.object(shared.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "cosign")):
            rejects(lambda: shared.verified_bytes(artifact, signature, "trusted-key", shared.sha256(payload), **kwargs))
        rejects(lambda: shared.regular_bytes(artifact, 1), "bound")
        print("VERIFICATION_OK")

    elif sys.argv[1] == "numerical":
        import numpy as np
        import torch
        from PIL import Image
        torch.set_num_threads(1)
        config = {"input_dim": 12, "hidden_dim": 3, "latent_dim": 2}
        preprocessing = {
            "schema_version": "aidefend.rgb-preprocessing.v1", "image_width": 2, "image_height": 2,
            "maximum_file_bytes": 4096, "maximum_pixels": 16, "accepted_formats": ["PNG"],
            "color_mode": "RGB", "resize": "BILINEAR", "layout": "CHW",
            "dtype": "float32", "value_scale": "uint8/255",
        }
        model = shared.make_model(config)
        with torch.no_grad():
            for value in model.parameters():
                value.zero_()
        torch.save(model.state_dict(), root / "model.pt")
        (root / "model.json").write_bytes(shared.canonical(config))
        (root / "preprocessing.json").write_bytes(shared.canonical(preprocessing))
        items = []
        for name, level in (("black", 0), ("grey", 12), ("white", 255)):
            file = root / (name + ".png")
            Image.new("RGB", (2, 2), (level, level, level)).save(file)
            if name != "white":
                items.append({"path": str(file), "sha256": shared.sha256(file.read_bytes())})
        (root / "holdout.json").write_bytes(shared.canonical({
            "schema_version": "aidefend.clean-media-manifest.v1", "items": items,
        }))
        declaration = policy()
        for key in ("model_config", "model_weights", "preprocessing", "clean_holdout"):
            declaration[key + "_sha256"] = shared.sha256(Path(declaration[key + "_path"]).read_bytes())
        runtime = shared.load_runtime(shared.canonical(declaration), maximum_artifact_bytes=1048576)
        reference = shared.build_reference(runtime, now=now)
        # Independent analytic oracle: zero reconstruction of black and grey images.
        expected_mean = (12 / 255) ** 2 / 2
        assert abs(reference["mean_mse"] - expected_mean) < 1e-8
        assert abs(reference["std_mse"] - expected_mean) < 1e-8
        captured = shared.canonical(reference)
        assert captured == shared.canonical(shared.build_reference(runtime, now=now))
        clean = (root / "black.png").read_bytes()
        anomaly = (root / "white.png").read_bytes()
        def score(raw, ref=captured, clock=now):
            return detector.score_reconstruction(image_bytes=raw, expected_image_sha256=shared.sha256(raw),
                runtime=runtime, reference_raw=ref, z_score_threshold=1, now=clock)
        assert score(clean)["finding_status"] == "NO_FINDING"
        result = score(anomaly)
        assert result["finding_status"] == "FINDING"
        assert result["mse"] == 1.0
        assert result["baseline_sha256"] == shared.sha256(captured)
        assert reference["measured_samples"] == declaration["expected_samples"] == 2
        rejects(lambda: score(clean, clock=datetime(2030, 1, 1, 13, tzinfo=timezone.utc)), "not currently valid")
        changed = {**reference, "preprocessing_sha256": "f" * 64}
        rejects(lambda: score(clean, ref=shared.canonical(changed)), "another release")
        rejects(lambda: score(b"malformed image"))
        rejects(lambda: score(b"x" * 4097), "byte bound")
        large = io.BytesIO()
        Image.new("RGB", (5, 5)).save(large, format="PNG")
        rejects(lambda: score(large.getvalue()), "pixel bound")
        rejects(lambda: detector.score_reconstruction(image_bytes=clean, expected_image_sha256="a" * 64,
            runtime=runtime, reference_raw=captured, z_score_threshold=1, now=now), "ingress")
        (root / "model.pt").write_bytes(b"wrong weights")
        rejects(lambda: shared.load_runtime(shared.canonical(declaration), maximum_artifact_bytes=1048576), "binding")
        print("NUMERICAL_HANDOFF_OK", json.dumps({"mean_mse": reference["mean_mse"],
                                                 "std_mse": reference["std_mse"], "anomaly_mse": result["mse"]}))
