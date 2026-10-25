"""Dashboard panels."""

from .audit_feed import SecurityPanel
from .cluster_health import ClusterPanel
from .iops_panel import IOPanel
from .mount_tree import MountTree

__all__ = ["ClusterPanel", "IOPanel", "MountTree", "SecurityPanel"]
