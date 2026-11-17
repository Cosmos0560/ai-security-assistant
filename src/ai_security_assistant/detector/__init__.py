"""Injection detector (D9, D10): weighted heuristics plus a per-run canary.

The injection patterns live ONLY in this package (D16). The naive mock provider must never
import them or share them: detection numbers would become circular.
"""
