"""Реализовать build_run_evidence по CONTRACT_RU.md."""
class RunEvidenceError(ValueError):
    def __init__(self, code):
        self.code=code
        super().__init__(code)
def build_run_evidence(report, *, release_id, bindings, attempt=1, command, test_artifacts):
    raise NotImplementedError('IMPLEMENTATION_REQUIRED')
