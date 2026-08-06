"""IFC plugin: FM-Agent stage hook entry points.

Thin orchestration layer. Stage implementations live in stage1.py / stage5.py /
stage6.py.
"""

from plugins.ifc.stage1 import replace_generate_phase_plan  # noqa: F401
from plugins.ifc.stage5 import replace_generate_topdown_layers  # noqa: F401
from plugins.ifc.stage6 import replace_generate_specs_and_verification  # noqa: F401
