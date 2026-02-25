from .kube_hunter import register_kube_hunter_tool
from .kube_bench import register_kube_bench_tool

__all__ = [
    'register_kube_hunter_tool',
    'register_kube_bench_tool'
]