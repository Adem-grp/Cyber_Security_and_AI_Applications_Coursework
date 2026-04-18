import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from main import ALGO_3DES, ALGO_AES_GCM, ALGO_CHACHA
from ui_tkinter import build_selection_warning


class TestUiWarnings(unittest.TestCase):
    def test_warning_present_when_3des_selected(self):
        message = build_selection_warning([ALGO_AES_GCM, ALGO_3DES])
        self.assertIsNotNone(message)
        self.assertIn("not recommended", message.lower())

    def test_warning_absent_without_3des(self):
        message = build_selection_warning([ALGO_AES_GCM, ALGO_CHACHA])
        self.assertIsNone(message)


if __name__ == "__main__":
    unittest.main(verbosity=2)

