# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple
from typing import Union

from drgn import Object
from drgn import TypeKind


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

            object_node = cls.get_node(
                name=type_.type_name(), address=object.address_
            )
            if object_node.object is None:
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
            self.object: Optional[Object] = None

        def __hash__(self):
            # Using name (example : "struct task_struct") and address as unique
            # Will be useful in case of Objects which don't exist in memory (example : CPU) - can set address=0 and name='CPU10'
            return hash((self.name, self.address))

        @classmethod
        def get_node(cls, name: str, address: int):
            hash_value = hash((name, address))
            if hash_value in DependencyGraph.node_map:
                return DependencyGraph.node_map[hash_value]
            return cls(name=name, address=address)

    node_map: Dict[int, Node] = dict()

    def __init__(self):
        pass

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
        cycles: List[List[DependencyGraph.Node]] = []
        parent: Dict[int, Optional[DependencyGraph.Node]] = dict()

        def dfs(start_node: DependencyGraph.Node) -> None:
            stack: List[
                Tuple[DependencyGraph.Node, Optional[DependencyGraph.Node]]
            ] = [(start_node, None)]
            while stack:
                node, parent_node = stack.pop()
                if node in visited:
                    continue
                visited.add(node)
                parent[hash(node)] = parent_node

                for neighbour in node.depends_on:
                    if neighbour not in visited:
                        stack.append((neighbour, node))
                    else:
                        cycle: List[DependencyGraph.Node] = []
                        cycle.append(neighbour)
                        temp: Optional[DependencyGraph.Node] = node
                        while temp and temp != neighbour:
                            cycle.append(temp)
                            temp = parent[hash(temp)]
                        cycle.append(neighbour)
                        cycle.reverse()
                        cycles.append(cycle)
                        return

        # Run DFS for all nodes in the graph
        for node in self.node_map.values():
            if node not in visited:  # Only visit unvisited nodes
                dfs(node)

        return cycles
