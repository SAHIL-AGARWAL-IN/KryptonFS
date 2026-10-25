"""The virtual mount tree, rebuilt from each tree message."""

from __future__ import annotations

from rich.text import Text
from textual.widgets import Tree
from textual.widgets.tree import TreeNode

from ..telemetry import TelemetryState, human_bytes

AUTO_EXPAND_DEPTH = 1  # directories this shallow start expanded


class MountTree(Tree[str]):
    def __init__(self, **kwargs) -> None:
        super().__init__(Text("/", style="bold #00e5ff"), data="/", **kwargs)
        self.show_root = True
        self._expanded: set[str] = {"/"}
        self._built_once = False

    def _remember_expansion(self, node: TreeNode[str]) -> None:
        for child in node.children:
            if child.data is not None and child.allow_expand:
                if child.is_expanded:
                    self._expanded.add(child.data)
                else:
                    self._expanded.discard(child.data)
                self._remember_expansion(child)

    def refresh_from(self, state: TelemetryState) -> None:
        if self._built_once:
            self._remember_expansion(self.root)
        self.clear()
        self.root.set_label(Text("/", style="bold #00e5ff"))
        dirs: dict[str, TreeNode[str]] = {"/": self.root}

        for entry in state.tree:
            path = entry.get("path", "")
            if path == "/" or not path.startswith("/"):
                continue
            parent_path, _, name = path.rpartition("/")
            parent = dirs.get(parent_path or "/")
            if parent is None:
                continue  # parent was cut off by truncation
            if entry.get("dir"):
                label = Text(f"{name}/", style="bold #00e5ff")
                node = parent.add(label, data=path)
                dirs[path] = node
                if (not self._built_once and entry.get("depth", 0) <= AUTO_EXPAND_DEPTH) or \
                        path in self._expanded:
                    node.expand()
            else:
                label = Text(name, style="#c9d4de")
                label.append(f"  {human_bytes(entry.get('size', 0))}", style="#7a8a99")
                parent.add_leaf(label, data=path)

        if state.tree_truncated:
            self.root.add_leaf(Text("… listing truncated", style="italic #ff6f61"))
        self.root.expand()
        self._built_once = True
