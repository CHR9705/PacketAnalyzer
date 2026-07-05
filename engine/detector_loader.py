# engine/detector_loader.py

import importlib
import pkgutil
import detectors


def load_detectors():
    detector_functions = []

    for _, module_name, _ in pkgutil.iter_modules(detectors.__path__):

        module = importlib.import_module(
            f"detectors.{module_name}"
        )

        if hasattr(module, "detect"):
            detector_functions.append(module.detect)

    return detector_functions