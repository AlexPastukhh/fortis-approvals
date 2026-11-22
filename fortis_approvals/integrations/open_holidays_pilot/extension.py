"""Generated entry: source-owned operations + preserved manual additions."""
# FORTIS-SOURCE-GENERATED-PROVIDER-V1
from fortis_approvals.extensions.source_generator import build_generated_provider
from .definition import SOURCE_DESCRIPTION
from . import manual
PROVIDER = build_generated_provider(SOURCE_DESCRIPTION,manual)
