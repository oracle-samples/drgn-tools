# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Union

from drgn import Object
from drgn import Program
from drgn import TypeKind

from drgn_tools.corelens import CorelensModule
from drgn_tools.lock import get_mutex_lock_info


class DependencyGraph:
    class Node:
        @classmethod
        def from_object(cls, object: Object):
            type_ = object.type_
            if type_.kind == TypeKind.POINTER:
                object = object[0]
                type_ = object.type_

            if type_.kind != TypeKind.STRUCT or object.address_ is None:
                raise ValueError(
                    "A reference object of type struct is expected"
                )

            object_node = cls(name=type_.typename(), address=object.address_)
            object_node.object = object
            return object_node

        def __init__(
            self,
            name: str,
            identifier: Union[int | str] = "",
            address: int = 0,
        ):
            self.name: str = f"{name}{str(identifier)}"
            self.address: int = address
            self.depends_on: List[DependencyGraph.Node] = []
            self.blocked_nodes: List[DependencyGraph.Node] = []
            self.object: Object = None

        def __hash__(self):
            # Using name (example : "struct task_struct") and address as unique
            # Will be useful in case of Objects which don't exist in memory (example : CPU) - can set address=0 and name='CPU10'
            return hash((self.name, self.address))

    def __init__(self):
        self.node_map: Dict[int, self.Node] = dict()

    def add_edge(self, src: Node, dst: Node) -> None:
        if hash(src) not in self.node_map:
            self.node_map[hash(src)] = src
        else:
            src = self.node_map[hash(src)]

        if hash(dst) not in self.node_map:
            self.node_map[hash(dst)] = dst
        else:
            dst = self.node_map[hash(dst)]

        if dst not in src.blocked_nodes:
            src.blocked_nodes.append(dst)

        if src not in dst.depends_on:
            dst.depends_on.append(src)

    def detect_cycle(self) -> Optional[List[List[Node]]]:
        visited: Set[DependencyGraph.Node] = set()
        path: List[DependencyGraph.Node] = []
        cycles: List[List[DependencyGraph.Node]] = []

        def dfs(node: DependencyGraph.Node) -> None:
            # If the node is currently being visited (part of the current DFS path), we've found a cycle
            if node in path:
                cycle_start = path.index(node)
                cycles.append(path[cycle_start:] + [node])
                return

            # If it's fully visited, no need to process this node again
            if node in visited:
                return

            visited.add(node)
            path.append(node)

            # Recursively visit all neighboring nodes
            for neighbor in node.depends_on:
                dfs(neighbor)

            path.pop()

        # Run DFS for all nodes in the graph
        for node in self.node_map.values():
            if node not in visited:  # Only visit unvisited nodes
                dfs(node)

        return cycles


class Deadlock(CorelensModule):
    name = "deadlock"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        pass

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        graph: DependencyGraph = DependencyGraph()
        get_mutex_lock_info(prog, stack=False, graph=graph)

        cycles = graph.detect_cycle()

        if not cycles:
            print("No cycle found")
            return

        for cycle in cycles:
            print(cycle)
