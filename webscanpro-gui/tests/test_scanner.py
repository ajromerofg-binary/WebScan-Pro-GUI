"""
tests/test_scanner.py

Pruebas unitarias para core/scanner.py: no lanzan la GUI ni el
subproceso completo, prueban la lógica de parseo y agregación en
aislamiento.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import strip_ansi, Finding, ScannerWorker, SCAN_MODULES


def test_strip_ansi_removes_color_codes():
    raw = "\x1b[0;31m[CRÍTICO]\x1b[0m Inyección SQL detectada"
    clean = strip_ansi(raw)
    assert clean == "[CRÍTICO] Inyección SQL detectada"
    assert "\x1b" not in clean


def test_strip_ansi_leaves_plain_text_untouched():
    raw = "línea sin colores ni control"
    assert strip_ansi(raw) == raw


def test_finding_from_json_roundtrip():
    d = {
        "id": "SH01", "name": "Falta HSTS", "severity": "ALTO",
        "category": "Security Headers", "description": "desc",
        "evidence": "evid", "recommendation": "rec",
    }
    f = Finding.from_json(d)
    assert f.id == "SH01"
    assert f.severity == "ALTO"
    assert f.name == "Falta HSTS"


def test_finding_from_json_missing_fields_does_not_crash():
    # Bug potencial: si el script cambia de formato o un campo llega vacío
    f = Finding.from_json({"id": "X01"})
    assert f.severity == "INFO"  # valor por defecto
    assert f.name == ""


def _make_worker(tmp_findings_path=None):
    w = ScannerWorker(script_path="dummy.sh", target_url="http://test.local")
    return w


def test_load_result_no_json_files_returns_none(tmp_path, monkeypatch):
    # Si no hay ningún /tmp/ws_findings_*.json, no debe reventar: debe
    # devolver None y dejar que la capa de arriba muestre un error claro.
    monkeypatch.chdir(tmp_path)
    import glob as glob_module
    monkeypatch.setattr(glob_module, "glob", lambda pattern: [])
    w = _make_worker()
    result = w._load_result("log vacío")
    assert result is None


def test_load_result_parses_findings_and_computes_score(tmp_path, monkeypatch):
    findings = [
        {"id": "SH01", "name": "Falta HSTS", "severity": "ALTO", "category": "Headers",
         "description": "d", "evidence": "e", "recommendation": "r"},
        {"id": "SQ01", "name": "SQLi", "severity": "CRITICO", "category": "SQLi",
         "description": "d", "evidence": "e", "recommendation": "r"},
        {"id": "SH05", "name": "Falta Referrer-Policy", "severity": "BAJO", "category": "Headers",
         "description": "d", "evidence": "e", "recommendation": "r"},
    ]
    json_path = tmp_path / "ws_findings_20260101_000000.json"
    json_path.write_text(json.dumps(findings), encoding="utf-8")

    import glob as glob_module
    monkeypatch.setattr(glob_module, "glob", lambda pattern: [str(json_path)])

    w = _make_worker()
    result = w._load_result("Directorio de salida: /tmp/salida_test")

    assert result is not None
    assert result.total == 3
    assert result.counts["CRITICO"] == 1
    assert result.counts["ALTO"] == 1
    assert result.counts["BAJO"] == 1
    # score = 1*10 (CRITICO) + 1*5 (ALTO) + 0*3 (MEDIO) + 1*1 (BAJO) = 16
    assert result.risk_score == 16
    assert result.risk_level == "ALTO"  # 16 >= 10 y < 20
    assert result.output_dir == "/tmp/salida_test"


def test_load_result_picks_most_recent_json_file(tmp_path, monkeypatch):
    # Bug potencial: si quedan JSONs de escaneos anteriores en /tmp,
    # debe coger el más reciente, no uno viejo al azar.
    old = tmp_path / "ws_findings_old.json"
    old.write_text(json.dumps([{"id": "OLD", "name": "viejo", "severity": "BAJO",
                                 "category": "x", "description": "", "evidence": "", "recommendation": ""}]))
    time.sleep(0.05)
    new = tmp_path / "ws_findings_new.json"
    new.write_text(json.dumps([{"id": "NEW", "name": "nuevo", "severity": "CRITICO",
                                 "category": "x", "description": "", "evidence": "", "recommendation": ""}]))

    import glob as glob_module
    monkeypatch.setattr(glob_module, "glob", lambda pattern: [str(old), str(new)])

    w = _make_worker()
    result = w._load_result("")
    assert result.findings[0].id == "NEW"


def test_load_result_handles_corrupt_json_gracefully(tmp_path, monkeypatch):
    # Bug potencial real: el script serializa manualmente el JSON con sed
    # (no con una librería JSON de verdad) — un carácter especial no
    # escapado en la evidencia (p.ej. una comilla suelta en una respuesta
    # HTTP) puede romper el JSON generado. La GUI no debe crashear.
    bad_json = tmp_path / "ws_findings_bad.json"
    bad_json.write_text('[{"id":"X", "name": "roto" "severity":}]', encoding="utf-8")

    import glob as glob_module
    monkeypatch.setattr(glob_module, "glob", lambda pattern: [str(bad_json)])

    w = _make_worker()
    result = w._load_result("")
    assert result is None  # no debe lanzar excepción, debe degradar limpiamente


def test_load_result_prefers_output_dir_copy_over_tmp(tmp_path, monkeypatch):
    # Caso real reportado: el canal /tmp falló (por el motivo que sea,
    # ajeno al escaneo en sí) pero la copia persistente en la carpeta
    # de salida SÍ existe (informe_hallazgos.json, escrita con
    # json.dump() real). No debe reportarse como escaneo fallido.
    findings = [
        {"id": "SH01", "name": "Falta HSTS", "severity": "ALTO", "category": "Headers",
         "description": "d", "evidence": "e", "recommendation": "r"},
    ]
    out_dir = tmp_path / "salida"
    out_dir.mkdir()
    (out_dir / "informe_hallazgos.json").write_text(json.dumps(findings), encoding="utf-8")

    import glob as glob_module
    # /tmp completamente vacío — si el código cayera al fallback, fallaría.
    monkeypatch.setattr(glob_module, "glob", lambda pattern: [])

    w = ScannerWorker(script_path="dummy.sh", target_url="http://test.local",
                       output_dir=str(out_dir))
    result = w._load_result("")

    assert result is not None
    assert result.total == 1
    assert result.findings[0].id == "SH01"


def test_load_result_falls_back_to_tmp_when_output_dir_copy_missing(tmp_path, monkeypatch):
    # Compatibilidad con motores antiguos que no escriban todavía
    # informe_hallazgos.json: debe seguir funcionando el canal /tmp.
    findings = [
        {"id": "SQ01", "name": "SQLi", "severity": "CRITICO", "category": "SQLi",
         "description": "d", "evidence": "e", "recommendation": "r"},
    ]
    out_dir = tmp_path / "salida_vacia"
    out_dir.mkdir()  # sin informe_hallazgos.json dentro

    json_path = tmp_path / "ws_findings_fallback.json"
    json_path.write_text(json.dumps(findings), encoding="utf-8")

    import glob as glob_module
    monkeypatch.setattr(glob_module, "glob", lambda pattern: [str(json_path)])

    w = ScannerWorker(script_path="dummy.sh", target_url="http://test.local",
                       output_dir=str(out_dir))
    result = w._load_result("")

    assert result is not None
    assert result.findings[0].id == "SQ01"


def test_all_modules_have_unique_keys():
    keys = [k for k, _ in SCAN_MODULES]
    assert len(keys) == len(set(keys))


def test_module_titles_are_unique_for_progress_matching():
    # Si dos títulos de módulo compartieran texto, el matching por
    # substring en ScannerWorker.run() confundiría el progreso.
    titles = [t for _, t in SCAN_MODULES]
    for i, t1 in enumerate(titles):
        for j, t2 in enumerate(titles):
            if i != j:
                assert t1 not in t2, f"'{t1}' es substring de '{t2}': el progreso se confundiría"
